/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  GTP-U user plane for the S8 emulation (3GPP TS 29.281).
 *
 *  Unlike SWu, where the kernel encapsulates (XFRM), GTP-U is done here in
 *  user space: the kernel's gtp driver picks the tunnel by UE address alone
 *  and cannot put a UE's RTP on a dedicated bearer's TEID. A forwarder
 *  thread of its own moves packets between one TUN device and the UDP 2152
 *  socket, so RTP does not wait for SIPp's main loop.
 *
 *  IPv4 only.
 */

#ifdef USE_S8

#include "gtpu.hpp"
#include "sipp.hpp"

#include <cerrno>
#include <cstring>
#include <map>
#include <string>
#include <vector>

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>

/* GTP-U message types (TS 29.281 §6.1) */
enum {
    GTPU_ECHO_REQUEST = 1, GTPU_ECHO_RESPONSE = 2, GTPU_ERROR_INDICATION = 26,
    GTPU_END_MARKER = 254, GTPU_GPDU = 255,
    GTPU_PORT = 2152,
    GTPU_IE_RECOVERY = 14       /* TS 29.281 §8.2 */
};

/* Inner MTU: what fits a 1500-byte path with outer IP, UDP and GTP-U in
 * front, with some room for a lower underlay MTU on the way to the PGW-U. */
#define GTPU_TUN_MTU 1400

struct GtpuBearer {
    uint32_t local_teid;        /* downlink arrives with this TEID */
    uint32_t peer_teid;         /* uplink is sent with this TEID */
    struct sockaddr_in peer;    /* PGW-U */
};

struct GtpuDedicated {
    uint8_t ebi;
    GtpuBearer bearer;
    std::vector<GtpuFilter> uplink;
    unsigned long ul_packets, dl_packets;
};

struct GtpuUe {
    GtpuBearer def;                         /* default bearer */
    std::vector<GtpuDedicated> dedicated;
};

/* Where a local TEID leads: the UE, and the dedicated bearer if it is one's */
struct GtpuTeidOwner {
    uint32_t ue;
    int ebi;                                /* -1: default bearer */
};

static pthread_mutex_t table_lock = PTHREAD_MUTEX_INITIALIZER;
static std::map<uint32_t, GtpuUe> by_ue;            /* UE address (network order) */
static std::map<uint32_t, GtpuTeidOwner> by_teid;   /* local TEID */

static int tun_fd = -1;
static int udp_fd = -1;
static char tun_name[IFNAMSIZ];
static unsigned int tun_ifindex;
static uint32_t route_table;
static pthread_t forwarder;
static bool forwarder_running;
static volatile bool forwarder_stop;
static std::string last_error;
static uint32_t next_teid;

const char *gtpu_error()
{
    return last_error.c_str();
}

/* --- codec -------------------------------------------------------------- */

std::vector<uint8_t> gtpu_encode_gpdu(uint32_t teid, const uint8_t *pkt, size_t len)
{
    /* Version 1, PT = 1 (GTP), no E/S/PN: TS 29.281 §5.1 */
    std::vector<uint8_t> out(8 + len);
    out[0] = 0x30;
    out[1] = GTPU_GPDU;
    out[2] = len >> 8;          /* length: everything after the 8 mandatory bytes */
    out[3] = len;
    out[4] = teid >> 24;
    out[5] = teid >> 16;
    out[6] = teid >> 8;
    out[7] = teid;
    memcpy(out.data() + 8, pkt, len);
    return out;
}

bool gtpu_decode(const uint8_t *msg, size_t len, GtpuMsg &out)
{
    if (len < 8 || (msg[0] >> 5) != 1 || !(msg[0] & 0x10)) {
        return false;           /* not GTPv1, or GTP' */
    }
    size_t body = ((size_t)msg[2] << 8) | msg[3];
    if (8 + body > len) {
        return false;
    }
    out.type = msg[1];
    out.teid = ((uint32_t)msg[4] << 24) | (msg[5] << 16) | (msg[6] << 8) | msg[7];
    out.has_seq = false;
    out.seq = 0;
    size_t off = 8;
    if (msg[0] & 0x07) {
        /* Any of E, S, PN set: sequence number (2), N-PDU number (1) and
         * next extension header type (1) are all present (§5.1). */
        if (body < 4) {
            return false;
        }
        out.has_seq = (msg[0] & 0x02) != 0;
        out.seq = (msg[8] << 8) | msg[9];
        uint8_t next = (msg[0] & 0x04) ? msg[11] : 0;
        off = 12;
        while (next != 0) {
            /* Extension header: length in 4-byte units, content, next type (§5.2) */
            if (off >= 8 + body || msg[off] == 0 || off + (size_t)msg[off] * 4 > 8 + body) {
                return false;
            }
            size_t ext = (size_t)msg[off] * 4;
            next = msg[off + ext - 1];
            off += ext;
        }
    }
    out.payload = msg + off;
    out.payload_len = 8 + body - off;
    return true;
}

/* --- rtnetlink ---------------------------------------------------------- */

static int rtnl_talk(struct nlmsghdr *nlh)
{
    char buf[1024];
    struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
    int rc = -1;

    if (!nl) {
        return -1;
    }
    nlh->nlmsg_seq = 1;
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) == 0 &&
        mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) >= 0) {
        ssize_t n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if (n > 0 && mnl_cb_run(buf, n, 1, mnl_socket_get_portid(nl), nullptr, nullptr) >= 0) {
            rc = 0;
        }
    }
    mnl_socket_close(nl);
    return rc;
}

/* UE address as a local /32 on the TUN device */
static int rtnl_addr(uint32_t addr, bool add)
{
    char buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
    struct ifaddrmsg *ifa = (struct ifaddrmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = 32;
    ifa->ifa_index = tun_ifindex;
    mnl_attr_put(nlh, IFA_LOCAL, 4, &addr);
    mnl_attr_put(nlh, IFA_ADDRESS, 4, &addr);
    return rtnl_talk(nlh);
}

/* "from <UE>/32 lookup <our table>": what a UE's sockets send leaves through
 * the TUN device whatever the destination, as its only way out is the bearer. */
static int rtnl_rule(uint32_t addr, bool add)
{
    char buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_EXCL : 0);
    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
    frh->family = AF_INET;
    frh->src_len = 32;
    frh->table = RT_TABLE_UNSPEC;
    frh->action = FR_ACT_TO_TBL;
    mnl_attr_put(nlh, FRA_SRC, 4, &addr);
    mnl_attr_put_u32(nlh, FRA_TABLE, route_table);
    return rtnl_talk(nlh);
}

/* "default dev <tun>" in our table */
static int rtnl_default_route()
{
    char buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    struct rtmsg *rtm = (struct rtmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
    rtm->rtm_family = AF_INET;
    rtm->rtm_table = RT_TABLE_UNSPEC;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope = RT_SCOPE_LINK;
    rtm->rtm_type = RTN_UNICAST;
    mnl_attr_put_u32(nlh, RTA_TABLE, route_table);
    mnl_attr_put_u32(nlh, RTA_OIF, tun_ifindex);
    return rtnl_talk(nlh);
}

/* --- uplink classification ---------------------------------------------- */

bool gtpu_filter_matches(const GtpuFilter &f, const uint8_t *pkt, size_t len)
{
    if (f.never || len < 20 || (pkt[0] >> 4) != 4) {
        return false;
    }
    size_t ihl = (size_t)(pkt[0] & 0x0f) * 4;
    uint32_t src, dst;
    memcpy(&src, pkt + 12, 4);
    memcpy(&dst, pkt + 16, 4);
    if ((src & f.local_mask) != (f.local_addr & f.local_mask) ||
        (dst & f.remote_mask) != (f.remote_addr & f.remote_mask)) {
        return false;
    }
    if (f.protocol >= 0 && pkt[9] != f.protocol) {
        return false;
    }
    bool ports_wanted = f.local_port_lo != 0 || f.local_port_hi != 65535 ||
                        f.remote_port_lo != 0 || f.remote_port_hi != 65535;
    if (!ports_wanted) {
        return true;
    }
    /* Ports exist in UDP, TCP and SCTP, and only in a first fragment */
    bool has_ports = pkt[9] == IPPROTO_UDP || pkt[9] == IPPROTO_TCP || pkt[9] == IPPROTO_SCTP;
    bool later_fragment = (((pkt[6] & 0x1f) << 8) | pkt[7]) != 0;
    if (!has_ports || later_fragment || ihl < 20 || len < ihl + 4) {
        return false;
    }
    uint16_t sport = (pkt[ihl] << 8) | pkt[ihl + 1];
    uint16_t dport = (pkt[ihl + 2] << 8) | pkt[ihl + 3];
    return sport >= f.local_port_lo && sport <= f.local_port_hi &&
           dport >= f.remote_port_lo && dport <= f.remote_port_hi;
}

/* Caller holds table_lock */
static GtpuDedicated *find_dedicated(uint32_t ue, int ebi)
{
    std::map<uint32_t, GtpuUe>::iterator it = by_ue.find(ue);
    if (it == by_ue.end()) {
        return nullptr;
    }
    for (size_t i = 0; i < it->second.dedicated.size(); i++) {
        if (it->second.dedicated[i].ebi == ebi) {
            return &it->second.dedicated[i];
        }
    }
    return nullptr;
}

/* --- forwarder thread --------------------------------------------------- */

static void forward_uplink(const uint8_t *pkt, size_t len)
{
    if (len < 20 || (pkt[0] >> 4) != 4) {
        return;                 /* IPv4 only */
    }
    uint32_t src;
    memcpy(&src, pkt + 12, 4);

    GtpuBearer bearer;
    pthread_mutex_lock(&table_lock);
    std::map<uint32_t, GtpuUe>::iterator it = by_ue.find(src);
    bool found = it != by_ue.end();
    if (found) {
        /* The filter with the lowest precedence value that the packet meets
         * names the bearer; without one it is the default bearer's
         * (TS 23.060 §15.3.2, TS 24.008 §10.5.6.12). */
        GtpuDedicated *best = nullptr;
        int best_precedence = 256;
        for (size_t i = 0; i < it->second.dedicated.size(); i++) {
            GtpuDedicated &d = it->second.dedicated[i];
            for (size_t k = 0; k < d.uplink.size(); k++) {
                if (d.uplink[k].precedence < best_precedence &&
                    gtpu_filter_matches(d.uplink[k], pkt, len)) {
                    best = &d;
                    best_precedence = d.uplink[k].precedence;
                }
            }
        }
        if (best) {
            best->ul_packets++;
            bearer = best->bearer;
        } else {
            bearer = it->second.def;
        }
    }
    pthread_mutex_unlock(&table_lock);
    if (!found) {
        return;
    }
    std::vector<uint8_t> msg = gtpu_encode_gpdu(bearer.peer_teid, pkt, len);
    sendto(udp_fd, msg.data(), msg.size(), 0, (struct sockaddr *)&bearer.peer, sizeof(bearer.peer));
}

static void forward_downlink(const uint8_t *msg, size_t len, const struct sockaddr_in &from)
{
    GtpuMsg m;
    if (!gtpu_decode(msg, len, m)) {
        return;
    }
    if (m.type == GTPU_ECHO_REQUEST) {
        /* Echo Response with the sequence number of the request and a
         * Recovery IE, whose value is not used on GTP-U (§7.2.2) */
        uint8_t rsp[14] = { 0x32, GTPU_ECHO_RESPONSE, 0, 6, 0, 0, 0, 0,
                            (uint8_t)(m.seq >> 8), (uint8_t)m.seq, 0, 0,
                            GTPU_IE_RECOVERY, 0 };
        sendto(udp_fd, rsp, sizeof(rsp), 0, (const struct sockaddr *)&from, sizeof(from));
        return;
    }
    if (m.type != GTPU_GPDU || m.payload_len < 20) {
        return;                 /* Error Indication, End Marker: nothing to do */
    }
    pthread_mutex_lock(&table_lock);
    std::map<uint32_t, GtpuTeidOwner>::iterator owner = by_teid.find(m.teid);
    bool known = owner != by_teid.end();
    if (known && owner->second.ebi >= 0) {
        GtpuDedicated *d = find_dedicated(owner->second.ue, owner->second.ebi);
        if (d) {
            d->dl_packets++;
        }
    }
    pthread_mutex_unlock(&table_lock);
    if (known) {
        if (write(tun_fd, m.payload, m.payload_len) < 0) {
            /* a full queue drops the packet, as any interface would */
        }
    }
}

static void *forwarder_main(void *)
{
    uint8_t buf[65536];
    struct pollfd fds[2] = { { tun_fd, POLLIN, 0 }, { udp_fd, POLLIN, 0 } };

    sigset_t mask;
    sigfillset(&mask);
    pthread_sigmask(SIG_BLOCK, &mask, nullptr);

    while (!forwarder_stop) {
        if (poll(fds, 2, 100) <= 0) {
            continue;
        }
        if (fds[0].revents & POLLIN) {
            ssize_t n = read(tun_fd, buf, sizeof(buf));
            if (n > 0) {
                forward_uplink(buf, n);
            }
        }
        if (fds[1].revents & POLLIN) {
            struct sockaddr_in from;
            socklen_t flen = sizeof(from);
            ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
            if (n > 0) {
                forward_downlink(buf, n, from);
            }
        }
    }
    return nullptr;
}

/* --- setup -------------------------------------------------------------- */

static bool fail(const char *what)
{
    last_error = std::string(what) + ": " + strerror(errno);
    return false;
}

static bool open_tun()
{
    struct ifreq ifr;

    tun_fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (tun_fd < 0) {
        return fail("cannot open /dev/net/tun");
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "sipps8_%d", (int)(getpid() % 100000));
    if (ioctl(tun_fd, TUNSETIFF, &ifr) < 0) {
        return fail("cannot create the TUN device (CAP_NET_ADMIN?)");
    }
    snprintf(tun_name, sizeof(tun_name), "%s", ifr.ifr_name);

    /* MTU and link state through an ordinary socket */
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    bool ok = s >= 0;
    if (ok) {
        ifr.ifr_mtu = GTPU_TUN_MTU;
        ok = ioctl(s, SIOCSIFMTU, &ifr) == 0 && ioctl(s, SIOCGIFFLAGS, &ifr) == 0;
        if (ok) {
            ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
            ok = ioctl(s, SIOCSIFFLAGS, &ifr) == 0;
        }
        close(s);
    }
    if (!ok) {
        return fail("cannot bring the TUN device up");
    }
    tun_ifindex = if_nametoindex(tun_name);
    return tun_ifindex != 0;
}

int gtpu_start(const char *local_ip)
{
    if (forwarder_running) {
        return 0;
    }
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(GTPU_PORT);
    if (inet_pton(AF_INET, local_ip, &local.sin_addr) != 1) {
        last_error = std::string("not an IPv4 address: ") + local_ip;
        return -1;
    }

    udp_fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (udp_fd < 0 || bind(udp_fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        fail("cannot bind the GTP-U socket (UDP 2152)");
        return -1;
    }
    if (!open_tun()) {
        return -1;
    }
    /* One table per process, so two SIPp instances on a host do not share one */
    route_table = 20000 + getpid() % 10000;
    if (rtnl_default_route() < 0) {
        fail("cannot install the route into the TUN device");
        return -1;
    }
    forwarder_stop = false;
    if (pthread_create(&forwarder, nullptr, forwarder_main, nullptr) != 0) {
        fail("cannot start the GTP-U forwarder thread");
        return -1;
    }
    forwarder_running = true;
    return 0;
}

uint32_t gtpu_new_teid()
{
    /* Start somewhere else on every run: a PGW may still hold bearers of a
     * previous run that ended without deleting them. */
    pthread_mutex_lock(&table_lock);
    if (next_teid == 0) {
        next_teid = 0x10000000u | ((uint32_t)(getpid() & 0xfff) << 16) | 1;
    }
    uint32_t teid = next_teid++;
    pthread_mutex_unlock(&table_lock);
    return teid;
}

int gtpu_add_ue(const char *ue_ip, uint32_t local_teid,
                const char *peer_ip, uint32_t peer_teid)
{
    uint32_t ue;
    GtpuBearer b;

    memset(&b, 0, sizeof(b));
    b.local_teid = local_teid;
    b.peer_teid = peer_teid;
    b.peer.sin_family = AF_INET;
    b.peer.sin_port = htons(GTPU_PORT);
    if (!forwarder_running || inet_pton(AF_INET, ue_ip, &ue) != 1 ||
        inet_pton(AF_INET, peer_ip, &b.peer.sin_addr) != 1) {
        last_error = "GTP-U not started, or not IPv4 addresses";
        return -1;
    }
    if (rtnl_addr(ue, true) < 0) {
        fail("cannot add the UE address to the TUN device");
        return -1;
    }
    /* The kernel drops every route through a device when its last address
     * goes, ours included: without this, the UE attached after the previous
     * one detached would send past the tunnel. */
    if (rtnl_default_route() < 0) {
        fail("cannot install the route into the TUN device");
        rtnl_addr(ue, false);
        return -1;
    }
    /* A rule left by a run that crashed would make this one fail with EEXIST */
    rtnl_rule(ue, false);
    if (rtnl_rule(ue, true) < 0) {
        fail("cannot add the source routing rule for the UE");
        rtnl_addr(ue, false);
        return -1;
    }
    GtpuUe entry;
    entry.def = b;
    GtpuTeidOwner owner = { ue, -1 };
    pthread_mutex_lock(&table_lock);
    by_ue[ue] = entry;
    by_teid[local_teid] = owner;
    pthread_mutex_unlock(&table_lock);
    return 0;
}

int gtpu_add_bearer(const char *ue_ip, uint8_t ebi, uint32_t local_teid,
                    const char *peer_ip, uint32_t peer_teid,
                    const std::vector<GtpuFilter> &uplink)
{
    uint32_t ue;
    GtpuDedicated d;

    d.ebi = ebi;
    d.uplink = uplink;
    d.ul_packets = d.dl_packets = 0;
    memset(&d.bearer, 0, sizeof(d.bearer));
    d.bearer.local_teid = local_teid;
    d.bearer.peer_teid = peer_teid;
    d.bearer.peer.sin_family = AF_INET;
    d.bearer.peer.sin_port = htons(GTPU_PORT);
    if (inet_pton(AF_INET, ue_ip, &ue) != 1 ||
        inet_pton(AF_INET, peer_ip, &d.bearer.peer.sin_addr) != 1) {
        last_error = "not IPv4 addresses";
        return -1;
    }
    int rc = -1;
    pthread_mutex_lock(&table_lock);
    std::map<uint32_t, GtpuUe>::iterator it = by_ue.find(ue);
    if (it != by_ue.end()) {
        GtpuDedicated *old = find_dedicated(ue, ebi);
        if (old) {
            by_teid.erase(old->bearer.local_teid);
            *old = d;
        } else {
            it->second.dedicated.push_back(d);
        }
        GtpuTeidOwner owner = { ue, ebi };
        by_teid[local_teid] = owner;
        rc = 0;
    } else {
        last_error = "no default bearer for this UE";
    }
    pthread_mutex_unlock(&table_lock);
    return rc;
}

void gtpu_set_filters(const char *ue_ip, uint8_t ebi, const std::vector<GtpuFilter> &uplink)
{
    uint32_t ue;
    if (inet_pton(AF_INET, ue_ip, &ue) != 1) {
        return;
    }
    pthread_mutex_lock(&table_lock);
    GtpuDedicated *d = find_dedicated(ue, ebi);
    if (d) {
        d->uplink = uplink;
    }
    pthread_mutex_unlock(&table_lock);
}

void gtpu_del_bearer(const char *ue_ip, uint8_t ebi)
{
    uint32_t ue;
    if (inet_pton(AF_INET, ue_ip, &ue) != 1) {
        return;
    }
    pthread_mutex_lock(&table_lock);
    std::map<uint32_t, GtpuUe>::iterator it = by_ue.find(ue);
    if (it != by_ue.end()) {
        std::vector<GtpuDedicated> &v = it->second.dedicated;
        for (size_t i = 0; i < v.size(); i++) {
            if (v[i].ebi == ebi) {
                by_teid.erase(v[i].bearer.local_teid);
                v.erase(v.begin() + i);
                break;
            }
        }
    }
    pthread_mutex_unlock(&table_lock);
}

bool gtpu_bearer_counters(const char *ue_ip, uint8_t ebi,
                          unsigned long &uplink, unsigned long &downlink)
{
    uint32_t ue;
    if (inet_pton(AF_INET, ue_ip, &ue) != 1) {
        return false;
    }
    pthread_mutex_lock(&table_lock);
    GtpuDedicated *d = find_dedicated(ue, ebi);
    if (d) {
        uplink = d->ul_packets;
        downlink = d->dl_packets;
    }
    pthread_mutex_unlock(&table_lock);
    return d != nullptr;
}

void gtpu_del_ue(const char *ue_ip)
{
    uint32_t ue;
    if (inet_pton(AF_INET, ue_ip, &ue) != 1) {
        return;
    }
    pthread_mutex_lock(&table_lock);
    std::map<uint32_t, GtpuUe>::iterator it = by_ue.find(ue);
    bool found = it != by_ue.end();
    if (found) {
        by_teid.erase(it->second.def.local_teid);
        for (size_t i = 0; i < it->second.dedicated.size(); i++) {
            by_teid.erase(it->second.dedicated[i].bearer.local_teid);
        }
        by_ue.erase(it);
    }
    pthread_mutex_unlock(&table_lock);
    if (found) {
        rtnl_rule(ue, false);
        rtnl_addr(ue, false);
    }
}

void gtpu_stop()
{
    if (!forwarder_running) {
        return;
    }
    forwarder_stop = true;
    pthread_join(forwarder, nullptr);
    forwarder_running = false;

    /* Addresses and the route go with the device; rules do not. */
    pthread_mutex_lock(&table_lock);
    std::map<uint32_t, GtpuUe> ues;
    ues.swap(by_ue);
    by_teid.clear();
    pthread_mutex_unlock(&table_lock);
    for (std::map<uint32_t, GtpuUe>::iterator it = ues.begin(); it != ues.end(); ++it) {
        rtnl_rule(it->first, false);
    }
    close(tun_fd);
    close(udp_fd);
    tun_fd = udp_fd = -1;
}

#ifdef GTEST
#include "gtest/gtest.h"

/* Reference bytes are from a capture of a live S1-U leg (visited SGW-U and
 * eNodeB, 2026-10-07): the header layout is the same on S8. */

/* Peers probe the path with Echo Request and take the tunnel endpoint for
 * dead when it goes unanswered, so the sequence number has to come back. */
TEST(Gtpu, DecodesCapturedEchoRequest) {
    const uint8_t echo[] = { 0x32, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00 };
    GtpuMsg m;
    ASSERT_TRUE(gtpu_decode(echo, sizeof(echo), m));
    EXPECT_EQ(GTPU_ECHO_REQUEST, m.type);
    EXPECT_TRUE(m.has_seq);
    EXPECT_EQ(0u, m.payload_len);
}

/* A G-PDU with the S flag carries 4 more header bytes before the T-PDU. If
 * they are taken for payload, every such packet is written to the TUN
 * device shifted by 4 bytes and dropped by the kernel as garbage. */
TEST(Gtpu, SkipsOptionalHeaderFieldsOfCapturedGpdu) {
    const uint8_t gpdu[] = { 0x32, 0xff, 0x00, 0x0c, 0x00, 0x00, 0x9e, 0xdf,
                             0x00, 0x00, 0x30, 0x00,
                             0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0xff };
    GtpuMsg m;
    ASSERT_TRUE(gtpu_decode(gpdu, sizeof(gpdu), m));
    EXPECT_EQ(GTPU_GPDU, m.type);
    EXPECT_EQ(0x9edfu, m.teid);
    ASSERT_EQ(8u, m.payload_len);
    EXPECT_EQ(0x60, m.payload[0]);      /* the inner IPv6 header */
}

TEST(Gtpu, SkipsExtensionHeaders) {
    /* E flag, one extension header of 4 bytes (type 0x85, PDU session
     * container), then the T-PDU */
    const uint8_t gpdu[] = { 0x34, 0xff, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x07,
                             0x00, 0x00, 0x00, 0x85,
                             0x01, 0x10, 0x09, 0x00,
                             0x45, 0x00, 0x00, 0x14 };
    GtpuMsg m;
    ASSERT_TRUE(gtpu_decode(gpdu, sizeof(gpdu), m));
    ASSERT_EQ(4u, m.payload_len);
    EXPECT_EQ(0x45, m.payload[0]);
}

/* The PGW-U finds the bearer by the TEID and trusts the length field. */
TEST(Gtpu, EncodesGpduThatDecodesBack) {
    const uint8_t ip[] = { 0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                           11, 12, 13, 14, 15, 16 };
    std::vector<uint8_t> msg = gtpu_encode_gpdu(0x12345678, ip, sizeof(ip));
    const uint8_t header[] = { 0x30, 0xff, 0x00, 0x14, 0x12, 0x34, 0x56, 0x78 };
    ASSERT_EQ(sizeof(header) + sizeof(ip), msg.size());
    EXPECT_EQ(0, memcmp(header, msg.data(), sizeof(header)));
    GtpuMsg m;
    ASSERT_TRUE(gtpu_decode(msg.data(), msg.size(), m));
    EXPECT_EQ(0x12345678u, m.teid);
    EXPECT_EQ(sizeof(ip), m.payload_len);
}

/* An uplink UDP packet 10.46.0.5:49170 -> 203.0.113.9:30000, as RTP is */
static std::vector<uint8_t> udp_packet(uint16_t sport, uint16_t dport, uint8_t proto = 17,
                                       uint16_t frag_off = 0)
{
    std::vector<uint8_t> p(28, 0);
    const uint8_t src[] = { 10, 46, 0, 5 }, dst[] = { 203, 0, 113, 9 };
    p[0] = 0x45;
    p[6] = frag_off >> 8;
    p[7] = frag_off;
    p[9] = proto;
    memcpy(&p[12], src, 4);
    memcpy(&p[16], dst, 4);
    p[20] = sport >> 8; p[21] = sport;
    p[22] = dport >> 8; p[23] = dport;
    return p;
}

/* The voice bearer's filter names the media gateway's address and port and
 * the UE's port. RTP has to go onto that bearer, and nothing else: SIP on
 * the dedicated bearer would be charged and policed as voice. */
TEST(Gtpu, UplinkFilterSelectsOnlyTheMediaFlow) {
    GtpuFilter f;
    f.protocol = 17;
    inet_pton(AF_INET, "203.0.113.9", &f.remote_addr);
    f.remote_mask = 0xffffffff;
    f.remote_port_lo = f.remote_port_hi = 30000;
    f.local_port_lo = f.local_port_hi = 49170;

    std::vector<uint8_t> rtp = udp_packet(49170, 30000);
    std::vector<uint8_t> sip = udp_packet(5060, 5060);
    std::vector<uint8_t> tcp = udp_packet(49170, 30000, 6);
    EXPECT_TRUE(gtpu_filter_matches(f, rtp.data(), rtp.size()));
    EXPECT_FALSE(gtpu_filter_matches(f, sip.data(), sip.size()));
    EXPECT_FALSE(gtpu_filter_matches(f, tcp.data(), tcp.size()));

    rtp[19] = 10;       /* another remote host */
    EXPECT_FALSE(gtpu_filter_matches(f, rtp.data(), rtp.size()));
}

/* A filter with a local address the UE does not have selects nothing, and a
 * later fragment has no ports to compare: both stay on the default bearer. */
TEST(Gtpu, UplinkFilterLocalAddressAndFragments) {
    GtpuFilter local;
    inet_pton(AF_INET, "10.46.0.0", &local.local_addr);
    inet_pton(AF_INET, "255.255.255.0", &local.local_mask);
    std::vector<uint8_t> pkt = udp_packet(1, 2);
    EXPECT_TRUE(gtpu_filter_matches(local, pkt.data(), pkt.size()));
    inet_pton(AF_INET, "10.47.0.0", &local.local_addr);
    EXPECT_FALSE(gtpu_filter_matches(local, pkt.data(), pkt.size()));

    GtpuFilter port;
    port.remote_port_lo = 30000;
    port.remote_port_hi = 30010;
    std::vector<uint8_t> first = udp_packet(49170, 30005);
    std::vector<uint8_t> later = udp_packet(49170, 30005, 17, 185);
    EXPECT_TRUE(gtpu_filter_matches(port, first.data(), first.size()));
    EXPECT_FALSE(gtpu_filter_matches(port, later.data(), later.size()));

    GtpuFilter any;                     /* no component: every IPv4 packet */
    EXPECT_TRUE(gtpu_filter_matches(any, later.data(), later.size()));
    any.never = true;                   /* e.g. an IPv6 address component */
    EXPECT_FALSE(gtpu_filter_matches(any, later.data(), later.size()));
}

TEST(Gtpu, RejectsTruncatedAndForeignMessages) {
    const uint8_t gtpv2[] = { 0x48, 0x20, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0 };
    const uint8_t cut[] = { 0x30, 0xff, 0x00, 0x20, 0, 0, 0, 1, 0x45 };
    GtpuMsg m;
    EXPECT_FALSE(gtpu_decode(gtpv2, sizeof(gtpv2), m));
    EXPECT_FALSE(gtpu_decode(cut, sizeof(cut), m));
}
#endif /* GTEST */

#endif /* USE_S8 */
