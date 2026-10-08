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
 *  SWu client for VoWiFi: IKEv2 initiator (RFC 7296) with EAP-AKA'
 *  (RFC 5448) or EAP-AKA (RFC 4187) toward an ePDG, 3GPP TS 24.302 §7.2 /
 *  TS 33.402 §8.
 *
 *  Deliberately minimal: one proposal (AES-CBC-256, HMAC-SHA2-256-128,
 *  PRF-HMAC-SHA2-256, MODP-2048), IPv4, EAP-only authentication of the
 *  ePDG (RFC 5998), no rekeying, no MOBIKE.
 */

#ifdef USE_SWU

#include "swu.hpp"
#include "sipp.hpp"
#include "xfrm_netlink.hpp"
#include "milenage.h"

#include <cstdarg>
#include <cstring>
#include <cerrno>
#include <set>

#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <linux/xfrm.h>
#include <linux/rtnetlink.h>
#include <linux/fib_rules.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <libmnl/libmnl.h>

#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

/* <linux/udp.h> clashes with <netinet/udp.h>, which sipp.hpp pulls in */
#ifndef UDP_ENCAP
#define UDP_ENCAP 100
#endif
#ifndef UDP_ENCAP_ESPINUDP
#define UDP_ENCAP_ESPINUDP 2
#endif

/* IKEv2 constants (RFC 7296 §3) */
enum {
    EXCH_IKE_SA_INIT = 34, EXCH_IKE_AUTH = 35, EXCH_INFORMATIONAL = 37,
    PL_SA = 33, PL_KE = 34, PL_IDI = 35, PL_IDR = 36, PL_AUTH = 39,
    PL_NONCE = 40, PL_NOTIFY = 41, PL_DELETE = 42, PL_TSI = 44, PL_TSR = 45,
    PL_SK = 46, PL_CP = 47, PL_EAP = 48,
    FLAG_INITIATOR = 0x08, FLAG_RESPONSE = 0x20,
    IKE_PORT = 500,
    N_NO_ADDITIONAL_SAS = 35, N_INITIAL_CONTACT = 16384, N_NAT_SRC = 16388,
    N_NAT_DST = 16389, N_COOKIE = 16390, N_EAP_ONLY = 16417,
    N_FIRST_STATUS = 16384,     /* notify types below this are errors */
    IKE_HDR_LEN = 28, IKE_NATT_PORT = 4500
};

/* EAP / EAP-AKA' constants (RFC 3748, RFC 4187 §11, RFC 5448) */
enum {
    EAP_REQUEST = 1, EAP_RESPONSE = 2, EAP_SUCCESS = 3, EAP_FAILURE = 4,
    EAP_TYPE_IDENTITY = 1, EAP_TYPE_AKA = 23, EAP_TYPE_AKA_PRIME = 50,
    AKA_CHALLENGE = 1, AKA_IDENTITY = 5, AKA_NOTIFICATION = 12,
    AT_RAND = 1, AT_AUTN = 2, AT_RES = 3, AT_MAC = 11, AT_NOTIFICATION = 12,
    AT_IDENTITY = 14, AT_KDF_INPUT = 23, AT_KDF = 24
};

#define SWU_RETRANS_MS   1000   /* first retransmission; doubles each time */
#define SWU_MAX_RETRANS  4
#define SWU_INNER_DEV    "lo"   /* inner addresses only have to be local */

static std::set<SwuSession *> all_sessions;
static std::set<SwuSession *> pending_sessions;     /* with an unanswered request */
static int swu_epfd = -1;
static uint32_t next_reqid = 0x10000;

/* --- byte helpers ------------------------------------------------------- */

static void put8(SwuBytes &b, uint8_t v) { b.push_back(v); }
static void put16(SwuBytes &b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xff); }
static void put32(SwuBytes &b, uint32_t v) { put16(b, v >> 16); put16(b, v & 0xffff); }
static void put(SwuBytes &b, const uint8_t *p, size_t n) { b.insert(b.end(), p, p + n); }
static void put(SwuBytes &b, const SwuBytes &o) { b.insert(b.end(), o.begin(), o.end()); }
static uint16_t get16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)get16(p) << 16) | get16(p + 2); }

static SwuBytes hmac256(const SwuBytes &key, const uint8_t *data, size_t len)
{
    SwuBytes out(32);
    unsigned int outlen = 32;
    HMAC(EVP_sha256(), key.data(), key.size(), data, len, out.data(), &outlen);
    return out;
}

static SwuBytes hmac256(const SwuBytes &key, const SwuBytes &data)
{
    return hmac256(key, data.data(), data.size());
}

static bool aes_cbc(bool encrypt, const SwuBytes &key, const uint8_t *iv,
                    const uint8_t *in, size_t len, SwuBytes &out)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n1 = 0, n2 = 0;
    out.resize(len + 16);
    bool ok = ctx &&
        EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv, encrypt) == 1 &&
        EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
        EVP_CipherUpdate(ctx, out.data(), &n1, in, len) == 1 &&
        EVP_CipherFinal_ex(ctx, out.data() + n1, &n2) == 1;
    EVP_CIPHER_CTX_free(ctx);
    out.resize(ok ? n1 + n2 : 0);
    return ok;
}

/* MODP-2048 (group 14, RFC 3526) with a 256-bit exponent */
static bool dh_compute(const SwuBytes *peer_pub, SwuBytes &priv, SwuBytes &out)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *p = BN_get_rfc3526_prime_2048(nullptr);
    BIGNUM *base = BN_new(), *x = BN_new(), *y = BN_new();
    bool ok = ctx && p && base && x && y;

    if (ok && peer_pub) {
        ok = BN_bin2bn(peer_pub->data(), peer_pub->size(), base) &&
             BN_bin2bn(priv.data(), priv.size(), x) &&
             !BN_is_zero(base) && !BN_is_one(base) && BN_cmp(base, p) < 0;
    } else if (ok) {
        ok = BN_set_word(base, 2) && BN_rand(x, 256, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY);
        if (ok) {
            priv.resize(32);
            BN_bn2binpad(x, priv.data(), 32);
        }
    }
    if (ok) {
        out.resize(256);
        ok = BN_mod_exp(y, base, x, p, ctx) && BN_bn2binpad(y, out.data(), 256) == 256;
    }
    BN_free(base);
    BN_clear_free(x);
    BN_clear_free(y);
    BN_free(p);
    BN_CTX_free(ctx);
    return ok;
}

/* --- key derivation ----------------------------------------------------- */

SwuBytes swu_prf_plus(const SwuBytes &key, const SwuBytes &seed, size_t len)
{
    SwuBytes out, t;
    for (uint8_t i = 1; out.size() < len; i++) {
        SwuBytes in(t);
        put(in, seed);
        put8(in, i);
        t = hmac256(key, in);
        put(out, t);
    }
    out.resize(len);
    return out;
}

void swu_aka_prime_ckik(const uint8_t ck[16], const uint8_t ik[16],
                        const std::string &network_name,
                        const uint8_t sqn_xor_ak[6],
                        uint8_t ck_prime[16], uint8_t ik_prime[16])
{
    SwuBytes key, s;
    put(key, ck, 16);
    put(key, ik, 16);
    put8(s, 0x20);      /* FC */
    put(s, (const uint8_t *)network_name.data(), network_name.size());
    put16(s, network_name.size());
    put(s, sqn_xor_ak, 6);
    put16(s, 6);
    SwuBytes h = hmac256(key, s);
    memcpy(ck_prime, h.data(), 16);
    memcpy(ik_prime, h.data() + 16, 16);
}

void swu_aka_prime_keys(const uint8_t ck_prime[16], const uint8_t ik_prime[16],
                        const std::string &identity, SwuAkaPrimeKeys &out)
{
    /* PRF' (RFC 5448 §3.4) is the same construction as IKEv2's prf+ */
    static const char label[] = "EAP-AKA'";
    SwuBytes key, s;
    put(key, ik_prime, 16);
    put(key, ck_prime, 16);
    put(s, (const uint8_t *)label, sizeof(label) - 1);
    put(s, (const uint8_t *)identity.data(), identity.size());
    SwuBytes mk = swu_prf_plus(key, s, 208);
    memcpy(out.k_encr, mk.data(), 16);
    memcpy(out.k_aut, mk.data() + 16, 32);
    memcpy(out.k_re, mk.data() + 48, 32);
    memcpy(out.msk, mk.data() + 80, 64);
    memcpy(out.emsk, mk.data() + 144, 64);
}

/* SHA-1 compression of one block without padding: "G" of FIPS 186-2 */
static void sha1_compress(uint32_t h[5], const uint8_t block[64])
{
    uint32_t w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
    for (int i = 0; i < 16; i++) {
        w[i] = get32(block + 4 * i);
    }
    for (int i = 16; i < 80; i++) {
        uint32_t x = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (x << 1) | (x >> 31);
    }
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e = d;
        d = c;
        c = (b << 30) | (b >> 2);
        b = a;
        a = t;
    }
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
}

/* FIPS 186-2 change notice 1 generator with b = 160 and no XSEED, as
 * profiled by RFC 4186 Appendix B / RFC 4187 §7 */
void swu_fips186_prf(const uint8_t mk[20], uint8_t *out, size_t len)
{
    uint8_t xkey[20];
    memcpy(xkey, mk, 20);
    for (size_t done = 0; done < len;) {
        uint32_t h[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
        uint8_t block[64], w[20];
        memset(block, 0, sizeof(block));
        memcpy(block, xkey, 20);
        sha1_compress(h, block);
        for (int i = 0; i < 5; i++) {
            w[4 * i] = h[i] >> 24;
            w[4 * i + 1] = h[i] >> 16;
            w[4 * i + 2] = h[i] >> 8;
            w[4 * i + 3] = h[i];
        }
        /* XKEY = (1 + XKEY + w) mod 2^160 */
        unsigned int carry = 1;
        for (int i = 19; i >= 0; i--) {
            carry += xkey[i] + w[i];
            xkey[i] = carry;
            carry >>= 8;
        }
        size_t n = len - done < 20 ? len - done : 20;
        memcpy(out + done, w, n);
        done += n;
    }
}

void swu_aka_keys(const uint8_t ck[16], const uint8_t ik[16],
                  const std::string &identity, SwuAkaKeys &out)
{
    SwuBytes in;
    uint8_t mk[SHA_DIGEST_LENGTH], keys[160];
    put(in, (const uint8_t *)identity.data(), identity.size());
    put(in, ik, 16);
    put(in, ck, 16);
    SHA1(in.data(), in.size(), mk);
    swu_fips186_prf(mk, keys, sizeof(keys));
    memcpy(out.k_encr, keys, 16);
    memcpy(out.k_aut, keys + 16, 16);
    memcpy(out.msk, keys + 32, 64);
    memcpy(out.emsk, keys + 96, 64);
}

/* AT_MAC: HMAC-SHA-256-128 for EAP-AKA', HMAC-SHA1-128 for EAP-AKA */
static SwuBytes aka_mac(bool prime, const SwuBytes &k_aut, const SwuBytes &packet)
{
    uint8_t md[EVP_MAX_MD_SIZE];
    unsigned int len = sizeof(md);
    HMAC(prime ? EVP_sha256() : EVP_sha1(), k_aut.data(), k_aut.size(),
         packet.data(), packet.size(), md, &len);
    return SwuBytes(md, md + 16);
}

/* --- inner address on the local host ------------------------------------ */

static int inner_addr(const char *ip, bool add)
{
    char buf[512];
    uint8_t a[16];
    int family = strchr(ip, ':') ? AF_INET6 : AF_INET;
    size_t alen = family == AF_INET ? 4 : 16;
    unsigned int ifindex = if_nametoindex(SWU_INNER_DEV);
    struct mnl_socket *nl;
    int rc = -1;

    if (!ifindex || inet_pton(family, ip, a) != 1) {
        return -1;
    }
    if (!(nl = mnl_socket_open(NETLINK_ROUTE))) {
        return -1;
    }
    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) == 0) {
        memset(buf, 0, sizeof(buf));
        struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
        nlh->nlmsg_type = add ? RTM_NEWADDR : RTM_DELADDR;
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
        nlh->nlmsg_seq = 1;
        struct ifaddrmsg *ifa = (struct ifaddrmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(*ifa));
        ifa->ifa_family = family;
        ifa->ifa_prefixlen = alen * 8;
        ifa->ifa_index = ifindex;
        /* No duplicate address detection: a tentative address cannot be
         * bound for a second, and nobody else is on this link */
        ifa->ifa_flags = family == AF_INET6 ? IFA_F_NODAD : 0;
        mnl_attr_put(nlh, IFA_LOCAL, alen, a);
        mnl_attr_put(nlh, IFA_ADDRESS, alen, a);
        if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) >= 0) {
            ssize_t n = mnl_socket_recvfrom(nl, buf, sizeof(buf));
            if (n > 0 && mnl_cb_run(buf, n, 1, mnl_socket_get_portid(nl), nullptr, nullptr) >= 0) {
                rc = 0;
            }
        }
    }
    mnl_socket_close(nl);
    return rc;
}

/*
 * Routing for an inner IPv6 address. The kernel only looks for an IPsec
 * policy once it has a route, and a host without IPv6 connectivity has none
 * for the destinations behind the tunnel: so every inner IPv6 address gets a
 * rule "from <address> lookup <our table>", and that table a default route.
 * The route's device does not matter, the policy sends the packet into the
 * tunnel. IPv4 needs nothing like it as long as the host has a default route.
 */
static uint32_t swu_route_table()
{
    return 21000 + getpid() % 1000;
}

static int rtnl_send(struct nlmsghdr *nlh)
{
    char buf[512];
    int rc = -1;
    struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
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

static int inner6_route(bool add)
{
    char buf[256];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = add ? RTM_NEWROUTE : RTM_DELROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_REPLACE : 0);
    struct rtmsg *rtm = (struct rtmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(*rtm));
    rtm->rtm_family = AF_INET6;
    rtm->rtm_table = RT_TABLE_UNSPEC;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope = RT_SCOPE_UNIVERSE;
    rtm->rtm_type = RTN_UNICAST;
    mnl_attr_put_u32(nlh, RTA_TABLE, swu_route_table());
    mnl_attr_put_u32(nlh, RTA_OIF, if_nametoindex(SWU_INNER_DEV));
    return rtnl_send(nlh);
}

static int inner6_rule(const char *ip6, bool add)
{
    char buf[256];
    uint8_t a[16];
    if (inet_pton(AF_INET6, ip6, a) != 1) {
        return -1;
    }
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = add ? RTM_NEWRULE : RTM_DELRULE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | (add ? NLM_F_CREATE | NLM_F_EXCL : 0);
    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)mnl_nlmsg_put_extra_header(nlh, sizeof(*frh));
    frh->family = AF_INET6;
    frh->src_len = 128;
    frh->table = RT_TABLE_UNSPEC;
    frh->action = FR_ACT_TO_TBL;
    mnl_attr_put(nlh, FRA_SRC, 16, a);
    mnl_attr_put_u32(nlh, FRA_TABLE, swu_route_table());
    return rtnl_send(nlh);
}

/*
 * A decrypted inner packet counts as received on the interface the ESP
 * packet came in on. If IPv6 is switched off there (the default in many
 * containers), the kernel discards every inner IPv6 packet: switch it on
 * for the interface that has our outer address. Best effort.
 */
static void enable_ipv6_on_outer(const std::string &outer_ip)
{
    struct ifaddrs *ifs = nullptr;
    struct in_addr want;
    if (inet_pton(AF_INET, outer_ip.c_str(), &want) != 1 || getifaddrs(&ifs) != 0) {
        return;
    }
    for (struct ifaddrs *i = ifs; i; i = i->ifa_next) {
        if (i->ifa_addr && i->ifa_addr->sa_family == AF_INET &&
            ((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr == want.s_addr) {
            char path[128];
            snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/disable_ipv6", i->ifa_name);
            int fd = open(path, O_RDWR);
            char cur = '0';
            if (fd >= 0) {
                if (read(fd, &cur, 1) == 1 && cur != '0' &&
                    (lseek(fd, 0, SEEK_SET) != 0 || write(fd, "0", 1) != 1)) {
                    WARNING("SWu: IPv6 is disabled on %s and cannot be enabled: inner IPv6 "
                            "packets will not be received", i->ifa_name);
                }
                close(fd);
            } else {
                WARNING("SWu: cannot check whether IPv6 is enabled on %s (%s): if it is not, "
                        "inner IPv6 packets will not be received", i->ifa_name, strerror(errno));
            }
            break;
        }
    }
    freeifaddrs(ifs);
}

/* --- IKEv2 encoding ----------------------------------------------------- */

static void put_transform(SwuBytes &b, bool last, uint8_t type, uint16_t id, int keylen)
{
    put8(b, last ? 0 : 3);
    put8(b, 0);
    put16(b, keylen ? 12 : 8);
    put8(b, type);
    put8(b, 0);
    put16(b, id);
    if (keylen) {
        put16(b, 0x800e);   /* Key Length attribute */
        put16(b, keylen);
    }
}

/* One proposal: AES-CBC-256 + HMAC-SHA2-256-128, for IKE or ESP */
static SwuBytes sa_body(bool esp, uint32_t esp_spi)
{
    SwuBytes t;
    put_transform(t, false, 1, 12, 256);    /* ENCR_AES_CBC */
    if (esp) {
        put_transform(t, false, 3, 12, 0);  /* AUTH_HMAC_SHA2_256_128 */
        put_transform(t, true, 5, 0, 0);    /* no ESN */
    } else {
        put_transform(t, false, 2, 5, 0);   /* PRF_HMAC_SHA2_256 */
        put_transform(t, false, 3, 12, 0);
        put_transform(t, true, 4, 14, 0);   /* MODP-2048 */
    }
    SwuBytes b;
    put8(b, 0);
    put8(b, 0);
    put16(b, 8 + (esp ? 4 : 0) + t.size());
    put8(b, 1);                 /* proposal number */
    put8(b, esp ? 3 : 1);       /* protocol: ESP / IKE */
    put8(b, esp ? 4 : 0);       /* SPI size */
    put8(b, esp ? 3 : 4);       /* number of transforms */
    if (esp) {
        put32(b, esp_spi);
    }
    put(b, t);
    return b;
}

static SwuBytes notify_body(uint16_t type, const SwuBytes &data = SwuBytes())
{
    SwuBytes b;
    put8(b, 0);     /* not about an existing SA */
    put8(b, 0);
    put16(b, type);
    put(b, data);
    return b;
}

static SwuBytes nat_hash(const uint8_t spi_i[8], const std::string &ip, uint16_t port)
{
    SwuBytes in, out(SHA_DIGEST_LENGTH);
    struct in_addr a;
    memset(&a, 0, sizeof(a));
    inet_pton(AF_INET, ip.c_str(), &a);
    put(in, spi_i, 8);
    in.resize(16, 0);   /* SPIr is still zero */
    put(in, (const uint8_t *)&a, 4);
    put16(in, port);
    SHA1(in.data(), in.size(), out.data());
    return out;
}

/* Walk a payload chain. Stops at SK, whose body is everything that is left. */
static bool parse_payloads(uint8_t type, const uint8_t *p, size_t len,
                           std::vector<std::pair<uint8_t, SwuBytes> > &out)
{
    size_t off = 0;
    while (type != 0) {
        if (off + 4 > len) {
            return false;
        }
        uint8_t next = p[off];
        size_t plen = get16(p + off + 2);
        if (plen < 4 || off + plen > len) {
            return false;
        }
        out.push_back(std::make_pair(type, SwuBytes(p + off + 4, p + off + plen)));
        if (type == PL_SK) {
            /* "next" names the first payload inside; keep it for the caller */
            out.back().second.insert(out.back().second.begin(), next);
            return true;
        }
        off += plen;
        type = next;
    }
    return true;
}

/* --- session ------------------------------------------------------------ */

SwuSession::SwuSession(const SwuConfig &cfg) :
    cfg_(cfg), state_(SWU_IDLE), fd_(-1),
    child_spi_i_(0), child_spi_r_(0),
    next_msgid_(0), retrans_at_(0), retrans_count_(0),
    last_peer_msgid_(0xffffffff),
    natt_(false), outer_port_(0), reqid_(0),
    sa_out_(false), sa_in_(false), pol_out_(false), pol_in_(false), addr_(false),
    pol6_out_(false), pol6_in_(false), addr6_(false)
{
    memset(spi_i_, 0, sizeof(spi_i_));
    memset(spi_r_, 0, sizeof(spi_r_));
    all_sessions.insert(this);
}

SwuSession::~SwuSession()
{
    if (state_ == SWU_ESTABLISHED) {
        /* Best effort: the owner is going away and cannot wait for the answer. */
        std::vector<Payload> pls(1);
        pls[0].type = PL_DELETE;
        put8(pls[0].body, 1);
        put8(pls[0].body, 0);
        put16(pls[0].body, 0);
        transmit(build_msg(EXCH_INFORMATIONAL, FLAG_INITIATOR, next_msgid_, pls, true));
    }
    remove_kernel();
    if (fd_ >= 0) {
        close(fd_);     /* also leaves the epoll set */
    }
    all_sessions.erase(this);
    pending_sessions.erase(this);
}

void SwuSession::set_pending(bool pending)
{
    if (pending) {
        pending_sessions.insert(this);
    } else {
        pending_.clear();
        pending_sessions.erase(this);
    }
}

void SwuSession::fail(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    error_ = buf;
    WARNING("SWu %s: %s", cfg_.identity.c_str(), buf);
    state_ = SWU_FAILED;
    set_pending(false);
    remove_kernel();
}

int SwuSession::start()
{
    struct addrinfo hints, *res = nullptr;
    struct sockaddr_in local;
    socklen_t len = sizeof(local);
    char addr[INET_ADDRSTRLEN];

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(cfg_.epdg.c_str(), "500", &hints, &res) != 0 || !res) {
        fail("cannot resolve ePDG '%s' (IPv4 only)", cfg_.epdg.c_str());
        return -1;
    }
    inet_ntop(AF_INET, &((struct sockaddr_in *)res->ai_addr)->sin_addr, addr, sizeof(addr));
    cfg_.epdg = addr;

    /* One socket and source port per UE. IKE_SA_INIT goes to port 500, all
     * later traffic to 4500 (see float_to_natt()), where the same socket also
     * carries this UE's UDP-encapsulated ESP. */
    fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    bool ok = fd_ >= 0;
    if (ok && !cfg_.local_ip.empty()) {
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        ok = inet_pton(AF_INET, cfg_.local_ip.c_str(), &local.sin_addr) == 1 &&
             bind(fd_, (struct sockaddr *)&local, sizeof(local)) == 0;
    }
    ok = ok && connect(fd_, res->ai_addr, res->ai_addrlen) == 0 &&
         getsockname(fd_, (struct sockaddr *)&local, &len) == 0;
    freeaddrinfo(res);
    if (!ok) {
        fail("cannot set up the IKE socket: %s", strerror(errno));
        return -1;
    }
    inet_ntop(AF_INET, &local.sin_addr, addr, sizeof(addr));
    outer_local_ = addr;
    outer_port_ = ntohs(local.sin_port);

    if (swu_epfd < 0) {
        swu_epfd = epoll_create1(0);
    }
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = this;
    if (swu_epfd < 0 || epoll_ctl(swu_epfd, EPOLL_CTL_ADD, fd_, &ev) < 0) {
        fail("cannot watch the IKE socket: %s", strerror(errno));
        return -1;
    }

    nonce_i_.resize(32);
    if (RAND_bytes(spi_i_, sizeof(spi_i_)) != 1 ||
        RAND_bytes(nonce_i_.data(), nonce_i_.size()) != 1 ||
        !dh_compute(nullptr, dh_priv_, dh_pub_)) {
        fail("cannot generate IKE key material");
        return -1;
    }

    state_ = SWU_INIT_SENT;
    init_req_ = build_init();
    pending_ = init_req_;
    retrans_count_ = 0;
    retrans_at_ = clock_tick + SWU_RETRANS_MS;
    set_pending(true);
    transmit(pending_);
    return 0;
}

SwuBytes SwuSession::build_init()
{
    std::vector<Payload> pls;
    Payload p;

    if (!cookie_.empty()) {
        p.type = PL_NOTIFY;
        p.body = notify_body(N_COOKIE, cookie_);
        pls.push_back(p);
    }
    p.type = PL_SA;
    p.body = sa_body(false, 0);
    pls.push_back(p);
    p.type = PL_KE;
    p.body.clear();
    put16(p.body, 14);
    put16(p.body, 0);
    put(p.body, dh_pub_);
    pls.push_back(p);
    p.type = PL_NONCE;
    p.body = nonce_i_;
    pls.push_back(p);
    p.type = PL_NOTIFY;
    p.body = notify_body(N_NAT_SRC, nat_hash(spi_i_, outer_local_, outer_port_));
    pls.push_back(p);
    p.body = notify_body(N_NAT_DST, nat_hash(spi_i_, cfg_.epdg, IKE_PORT));
    pls.push_back(p);
    return build_msg(EXCH_IKE_SA_INIT, FLAG_INITIATOR, 0, pls, false);
}

SwuBytes SwuSession::build_msg(uint8_t exchange, uint8_t flags, uint32_t msgid,
                               const std::vector<Payload> &pls, bool encrypt)
{
    SwuBytes chain;
    for (size_t i = 0; i < pls.size(); i++) {
        put8(chain, i + 1 < pls.size() ? pls[i + 1].type : 0);
        put8(chain, 0);
        put16(chain, 4 + pls[i].body.size());
        put(chain, pls[i].body);
    }
    uint8_t first = pls.empty() ? 0 : pls[0].type;

    SwuBytes msg;
    put(msg, spi_i_, 8);
    put(msg, spi_r_, 8);
    put8(msg, encrypt ? PL_SK : first);
    put8(msg, 0x20);    /* IKEv2 */
    put8(msg, exchange);
    put8(msg, flags);
    put32(msg, msgid);
    put32(msg, 0);      /* length, below */

    if (!encrypt) {
        put(msg, chain);
    } else {
        /* SK { IV | AES-CBC(payloads | padding | pad length) | ICV } */
        uint8_t iv[16];
        RAND_bytes(iv, sizeof(iv));
        size_t padlen = 15 - (chain.size() % 16);
        chain.resize(chain.size() + padlen, 0);
        put8(chain, padlen);
        SwuBytes enc;
        aes_cbc(true, sk_ei_, iv, chain.data(), chain.size(), enc);
        put8(msg, first);
        put8(msg, 0);
        put16(msg, 4 + 16 + enc.size() + 16);
        put(msg, iv, 16);
        put(msg, enc);
    }

    uint32_t total = msg.size() + (encrypt ? 16 : 0);
    msg[24] = total >> 24;
    msg[25] = total >> 16;
    msg[26] = total >> 8;
    msg[27] = total;
    if (encrypt) {
        SwuBytes icv = hmac256(sk_ai_, msg);
        put(msg, icv.data(), 16);
    }
    return msg;
}

/*
 * Move to UDP 4500 whether or not a NAT was detected (RFC 7296 §2.23 allows
 * it): the ePDG then installs UDP-encapsulated ESP, which is what lets many
 * UEs share one source address, each on its own port.
 */
bool SwuSession::float_to_natt()
{
    struct sockaddr_in dst;
    int encap = UDP_ENCAP_ESPINUDP;

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(IKE_NATT_PORT);
    /* Only now: with UDP_ENCAP set, the kernel takes every datagram that does
     * not start with the non-ESP marker for ESP, as port 500 IKE would. */
    natt_ = inet_pton(AF_INET, cfg_.epdg.c_str(), &dst.sin_addr) == 1 &&
            connect(fd_, (struct sockaddr *)&dst, sizeof(dst)) == 0 &&
            setsockopt(fd_, IPPROTO_UDP, UDP_ENCAP, &encap, sizeof(encap)) == 0;
    return natt_;
}

void SwuSession::transmit(const SwuBytes &msg)
{
    SwuBytes dgram(natt_ ? 4 : 0, 0);   /* non-ESP marker (RFC 3948 §2.2) */
    put(dgram, msg);
    if (fd_ >= 0 && send(fd_, dgram.data(), dgram.size(), 0) < 0) {
        WARNING("SWu %s: send to ePDG failed: %s", cfg_.identity.c_str(), strerror(errno));
    }
}

void SwuSession::send_request(uint8_t exchange, const std::vector<Payload> &pls, bool encrypt)
{
    pending_ = build_msg(exchange, FLAG_INITIATOR, next_msgid_, pls, encrypt);
    retrans_count_ = 0;
    retrans_at_ = clock_tick + SWU_RETRANS_MS;
    set_pending(true);
    transmit(pending_);
}

void SwuSession::on_timer()
{
    if (pending_.empty() || clock_tick < retrans_at_) {
        return;
    }
    if (retrans_count_ >= SWU_MAX_RETRANS) {
        if (state_ == SWU_DELETING) {
            /* The ePDG will notice by DPD; our side is gone either way. */
            set_pending(false);
            remove_kernel();
            state_ = SWU_CLOSED;
        } else {
            fail("no response from ePDG %s", cfg_.epdg.c_str());
        }
        return;
    }
    retrans_count_++;
    retrans_at_ = clock_tick + (SWU_RETRANS_MS << retrans_count_);
    transmit(pending_);
}

void SwuSession::on_readable()
{
    uint8_t buf[4096];
    for (int i = 0; i < 16; i++) {
        ssize_t n = recv(fd_, buf, sizeof(buf), 0);
        if (n <= 0) {
            return;
        }
        on_datagram(buf, n);
    }
}

void SwuSession::on_datagram(const uint8_t *data, size_t len)
{
    const uint8_t *msg = data;
    if (natt_) {
        /* NAT keepalive, or not IKE: ESP never gets here (kernel UDP encap) */
        if (len < 4 || get32(data) != 0) {
            return;
        }
        msg += 4;
        len -= 4;
    }
    if (len < IKE_HDR_LEN || memcmp(msg, spi_i_, 8) != 0 || get32(msg + 24) != len) {
        return;
    }
    uint8_t first = msg[16], exchange = msg[18], flags = msg[19];
    uint32_t msgid = get32(msg + 20);

    if (flags & FLAG_RESPONSE) {
        if (!pending_.empty() && msgid == next_msgid_) {
            on_response(exchange, first, msg, len);
        }
    } else {
        on_request(exchange, msgid, first, msg, len);
    }
}

bool SwuSession::decrypt(uint8_t first, const uint8_t *msg, size_t len, std::vector<Payload> &out)
{
    std::vector<std::pair<uint8_t, SwuBytes> > outer, inner;
    if (sk_ar_.empty() || !parse_payloads(first, msg + IKE_HDR_LEN, len - IKE_HDR_LEN, outer) ||
        outer.empty() || outer.back().first != PL_SK) {
        return false;
    }
    /* body = first inner type | IV(16) | ciphertext | ICV(16), and SK is last */
    const SwuBytes &sk = outer.back().second;
    if (sk.size() < 1 + 16 + 16 + 16 || (sk.size() - 1) % 16 != 0) {
        return false;
    }
    SwuBytes icv = hmac256(sk_ar_, msg, len - 16);
    if (CRYPTO_memcmp(icv.data(), msg + len - 16, 16) != 0) {
        return false;
    }
    SwuBytes plain;
    if (!aes_cbc(false, sk_er_, sk.data() + 1, sk.data() + 17, sk.size() - 33, plain) ||
        plain.empty() || (size_t)plain.back() + 1 > plain.size()) {
        return false;
    }
    if (!parse_payloads(sk[0], plain.data(), plain.size() - 1 - plain.back(), inner)) {
        return false;
    }
    for (size_t i = 0; i < inner.size(); i++) {
        Payload p;
        p.type = inner[i].first;
        p.body = inner[i].second;
        out.push_back(p);
    }
    return true;
}

void SwuSession::on_response(uint8_t exchange, uint8_t first, const uint8_t *msg, size_t len)
{
    if (state_ == SWU_INIT_SENT) {
        if (exchange == EXCH_IKE_SA_INIT) {
            handle_init_response(first, msg, len);
        }
        return;
    }

    std::vector<Payload> pls;
    if (!decrypt(first, msg, len, pls)) {
        return;     /* not from the ePDG, or damaged: keep waiting */
    }
    set_pending(false);
    next_msgid_++;

    if (state_ == SWU_DELETING) {
        remove_kernel();
        state_ = SWU_CLOSED;
    } else if (exchange == EXCH_IKE_AUTH &&
               (state_ == SWU_AUTH_EAP || state_ == SWU_AUTH_FINAL)) {
        handle_auth_response(pls);
    }
}

void SwuSession::handle_init_response(uint8_t first, const uint8_t *msg, size_t len)
{
    std::vector<std::pair<uint8_t, SwuBytes> > pls;
    SwuBytes ke;

    if (!parse_payloads(first, msg + IKE_HDR_LEN, len - IKE_HDR_LEN, pls)) {
        return;
    }
    for (size_t i = 0; i < pls.size(); i++) {
        const SwuBytes &b = pls[i].second;
        if (pls[i].first == PL_NOTIFY && b.size() >= 4) {
            uint16_t type = get16(b.data() + 2);
            if (type == N_COOKIE && cookie_.empty()) {
                /* RFC 7296 §2.6: repeat the request with the cookie */
                cookie_.assign(b.begin() + 4 + b[1], b.end());
                init_req_ = build_init();
                pending_ = init_req_;
                retrans_count_ = 0;
                retrans_at_ = clock_tick + SWU_RETRANS_MS;
                transmit(pending_);
                return;
            }
            if (type < N_FIRST_STATUS) {
                fail("IKE_SA_INIT rejected by the ePDG (notify %u)", type);
                return;
            }
        } else if (pls[i].first == PL_KE && b.size() == 4 + 256 && get16(b.data()) == 14) {
            ke.assign(b.begin() + 4, b.end());
        } else if (pls[i].first == PL_NONCE) {
            nonce_r_ = b;
        }
    }
    SwuBytes shared;
    if (ke.empty() || nonce_r_.size() < 16 || !dh_compute(&ke, dh_priv_, shared)) {
        fail("IKE_SA_INIT response without usable KE/nonce (MODP-2048 expected)");
        return;
    }

    memcpy(spi_r_, msg + 8, 8);
    init_resp_.assign(msg, msg + len);
    if (!float_to_natt()) {
        fail("cannot move the IKE socket to UDP 4500: %s", strerror(errno));
        return;
    }
    derive_ike_keys(shared);
    set_pending(false);
    next_msgid_ = 1;
    state_ = SWU_AUTH_EAP;
    send_auth_first();
}

void SwuSession::derive_ike_keys(const SwuBytes &shared)
{
    /* RFC 7296 §2.14 */
    SwuBytes nonces(nonce_i_);
    put(nonces, nonce_r_);
    SwuBytes skeyseed = hmac256(nonces, shared);
    SwuBytes seed(nonces);
    put(seed, spi_i_, 8);
    put(seed, spi_r_, 8);
    SwuBytes km = swu_prf_plus(skeyseed, seed, 7 * 32);
    SwuBytes *keys[] = { &sk_d_, &sk_ai_, &sk_ar_, &sk_ei_, &sk_er_, &sk_pi_, &sk_pr_ };
    for (int i = 0; i < 7; i++) {
        keys[i]->assign(km.begin() + i * 32, km.begin() + (i + 1) * 32);
    }
}

void SwuSession::send_auth_first()
{
    std::vector<Payload> pls;
    Payload p;

    /* IDi: the NAI (TS 24.302 §7.2.2.1) */
    put8(idi_body_, 3);     /* ID_RFC822_ADDR */
    idi_body_.resize(4, 0);
    put(idi_body_, (const uint8_t *)cfg_.identity.data(), cfg_.identity.size());
    p.type = PL_IDI;
    p.body = idi_body_;
    pls.push_back(p);

    p.type = PL_NOTIFY;
    p.body = notify_body(N_INITIAL_CONTACT);
    pls.push_back(p);

    /* IDr: the APN (TS 24.302 §7.2.2.1) */
    if (!cfg_.apn.empty()) {
        p.type = PL_IDR;
        p.body.clear();
        put8(p.body, 2);    /* ID_FQDN */
        p.body.resize(4, 0);
        put(p.body, (const uint8_t *)cfg_.apn.data(), cfg_.apn.size());
        pls.push_back(p);
    }

    /* CFG_REQUEST: inner address, DNS and P-CSCF (RFC 7651) for each
     * address family wanted. Which INTERNAL_IPx_ADDRESS attributes are there
     * tells the ePDG the PDN type to ask the PGW for (TS 24.302 §7.2.2). */
    bool want4 = cfg_.pdn_type != 2, want6 = cfg_.pdn_type == 2 || cfg_.pdn_type == 3;
    p.type = PL_CP;
    p.body.clear();
    put8(p.body, 1);
    p.body.resize(4, 0);
    static const uint16_t attrs4[] = { 1 /* INTERNAL_IP4_ADDRESS */, 3 /* INTERNAL_IP4_DNS */,
                                       20 /* P_CSCF_IP4_ADDRESS */ };
    static const uint16_t attrs6[] = { 8 /* INTERNAL_IP6_ADDRESS */, 10 /* INTERNAL_IP6_DNS */,
                                       21 /* P_CSCF_IP6_ADDRESS */ };
    for (size_t i = 0; i < 3; i++) {
        if (want4) {
            put16(p.body, attrs4[i]);
            put16(p.body, 0);
        }
    }
    for (size_t i = 0; i < 3; i++) {
        if (want6) {
            put16(p.body, attrs6[i]);
            put16(p.body, 0);
        }
    }
    pls.push_back(p);

    do {
        RAND_bytes((uint8_t *)&child_spi_i_, sizeof(child_spi_i_));
    } while (child_spi_i_ < 256);
    p.type = PL_SA;
    p.body = sa_body(true, child_spi_i_);
    pls.push_back(p);

    /* TSi / TSr: any address of each family wanted (RFC 7296 §3.13.1); the
     * ePDG narrows TSi to the inner addresses */
    p.body.clear();
    put8(p.body, (want4 ? 1 : 0) + (want6 ? 1 : 0));
    p.body.resize(4, 0);
    if (want4) {
        put8(p.body, 7);        /* TS_IPV4_ADDR_RANGE */
        put8(p.body, 0);
        put16(p.body, 16);
        put16(p.body, 0);
        put16(p.body, 65535);
        put32(p.body, 0);
        put32(p.body, 0xffffffff);
    }
    if (want6) {
        put8(p.body, 8);        /* TS_IPV6_ADDR_RANGE */
        put8(p.body, 0);
        put16(p.body, 40);
        put16(p.body, 0);
        put16(p.body, 65535);
        p.body.insert(p.body.end(), 16, 0x00);
        p.body.insert(p.body.end(), 16, 0xff);
    }
    p.type = PL_TSI;
    pls.push_back(p);
    p.type = PL_TSR;
    pls.push_back(p);

    /* No AUTH payload: we authenticate with EAP, and accept the ePDG doing
     * the same with the MSK instead of a certificate (RFC 5998). */
    p.type = PL_NOTIFY;
    p.body = notify_body(N_EAP_ONLY);
    pls.push_back(p);

    send_request(EXCH_IKE_AUTH, pls, true);
}

SwuBytes SwuSession::auth_octets(bool initiator)
{
    /* RFC 7296 §2.15 */
    SwuBytes octets(initiator ? init_req_ : init_resp_);
    put(octets, initiator ? nonce_r_ : nonce_i_);
    put(octets, hmac256(initiator ? sk_pi_ : sk_pr_, initiator ? idi_body_ : idr_body_));
    return octets;
}

void SwuSession::handle_auth_response(const std::vector<Payload> &pls)
{
    const SwuBytes *eap = nullptr;

    for (size_t i = 0; i < pls.size(); i++) {
        const SwuBytes &b = pls[i].body;
        if (pls[i].type == PL_NOTIFY && b.size() >= 4 && get16(b.data() + 2) < N_FIRST_STATUS) {
            fail("IKE_AUTH rejected by the ePDG (notify %u)", get16(b.data() + 2));
            return;
        } else if (pls[i].type == PL_IDR) {
            idr_body_ = b;
        } else if (pls[i].type == PL_EAP) {
            eap = &b;
        }
    }

    if (state_ == SWU_AUTH_FINAL) {
        finish_auth(pls);
        return;
    }
    if (!eap) {
        fail("IKE_AUTH response without EAP payload");
        return;
    }

    SwuBytes reply;
    bool success = false;
    if (!handle_eap(*eap, reply, success)) {
        return;
    }
    std::vector<Payload> out(1);
    if (success) {
        /* AUTH = prf(prf(MSK, "Key Pad for IKEv2"), <InitiatorSignedOctets>) */
        static const char pad[] = "Key Pad for IKEv2";
        SwuBytes key = hmac256(msk_, (const uint8_t *)pad, sizeof(pad) - 1);
        out[0].type = PL_AUTH;
        put8(out[0].body, 2);   /* shared key message integrity code */
        out[0].body.resize(4, 0);
        put(out[0].body, hmac256(key, auth_octets(true)));
        state_ = SWU_AUTH_FINAL;
    } else {
        out[0].type = PL_EAP;
        out[0].body = reply;
    }
    send_request(EXCH_IKE_AUTH, out, true);
}

bool SwuSession::handle_eap(const SwuBytes &eap, SwuBytes &reply, bool &success)
{
    if (eap.size() < 4) {
        fail("truncated EAP packet");
        return false;
    }
    uint8_t code = eap[0], id = eap[1];

    if (code == EAP_SUCCESS) {
        if (msk_.empty()) {
            fail("EAP-Success before the AKA challenge");
            return false;
        }
        success = true;
        return true;
    }
    if (code != EAP_REQUEST || eap.size() < 5) {
        fail(code == EAP_FAILURE ? "EAP-Failure from the AAA server (subscriber or keys rejected)"
                                 : "unexpected EAP packet");
        return false;
    }

    const std::string &identity = cfg_.identity;
    uint8_t type = eap[4];
    if (type == EAP_TYPE_IDENTITY) {
        put8(reply, EAP_RESPONSE);
        put8(reply, id);
        put16(reply, 5 + identity.size());
        put8(reply, EAP_TYPE_IDENTITY);
        put(reply, (const uint8_t *)identity.data(), identity.size());
        return true;
    }
    if ((type != EAP_TYPE_AKA_PRIME && type != EAP_TYPE_AKA) || eap.size() < 8) {
        fail("unsupported EAP method %u", type);
        return false;
    }

    switch (eap[5]) {
    case AKA_CHALLENGE:
        return handle_aka_challenge(eap, reply);
    case AKA_IDENTITY: {
        /* AT_*_ID_REQ: answer with the permanent identity */
        size_t padded = (identity.size() + 3) & ~3u;
        put8(reply, EAP_RESPONSE);
        put8(reply, id);
        put16(reply, 8 + 4 + padded);
        put8(reply, type);
        put8(reply, AKA_IDENTITY);
        put16(reply, 0);
        put8(reply, AT_IDENTITY);
        put8(reply, 1 + padded / 4);
        put16(reply, identity.size());
        put(reply, (const uint8_t *)identity.data(), identity.size());
        reply.resize(8 + 4 + padded, 0);
        return true;
    }
    default:
        fail("EAP-AKA subtype %u from the AAA server (12 = notification, i.e. rejected)", eap[5]);
        return false;
    }
}

bool SwuSession::handle_aka_challenge(const SwuBytes &eap, SwuBytes &reply)
{
    const bool prime = eap[4] == EAP_TYPE_AKA_PRIME;
    const uint8_t *rand = nullptr, *autn = nullptr;
    size_t mac_off = 0;
    std::string network_name;
    int kdf = -1;

    for (size_t off = 8; off + 2 <= eap.size();) {
        uint8_t type = eap[off];
        size_t alen = eap[off + 1] * 4;
        if (alen == 0 || off + alen > eap.size()) {
            fail("malformed EAP-AKA attribute");
            return false;
        }
        if (type == AT_RAND && alen == 20) {
            rand = &eap[off + 4];
        } else if (type == AT_AUTN && alen == 20) {
            autn = &eap[off + 4];
        } else if (type == AT_MAC && alen == 20) {
            mac_off = off + 4;
        } else if (type == AT_KDF && alen == 4 && kdf < 0) {
            kdf = get16(&eap[off + 2]);
        } else if (type == AT_KDF_INPUT && alen >= 4 && (size_t)get16(&eap[off + 2]) <= alen - 4) {
            network_name.assign((const char *)&eap[off + 4], get16(&eap[off + 2]));
        }
        off += alen;
    }
    if (!rand || !autn || !mac_off || (prime && (network_name.empty() || kdf != 1))) {
        fail("EAP-AKA challenge lacks RAND, AUTN or MAC (or KDF 1 / KDF_INPUT for AKA')");
        return false;
    }

    /* USIM side of AKA (TS 33.102 §6.3.3), Milenage */
    uint8_t res[16], ck[16], ik[16], ak[6], sqn[6], xmac[8], rnd[16], amf[2];
    memcpy(rnd, rand, 16);
    memcpy(amf, autn + 6, 2);
    f2345(cfg_.k, rnd, res, ck, ik, ak, cfg_.opc, 1);
    for (int i = 0; i < 6; i++) {
        sqn[i] = autn[i] ^ ak[i];
    }
    f1(cfg_.k, rnd, sqn, amf, xmac, cfg_.opc, 1);
    if (CRYPTO_memcmp(xmac, autn + 8, 8) != 0) {
        fail("AUTN does not verify: K/OPc do not match the HSS");
        return false;
    }

    SwuBytes k_aut, msk;
    if (prime) {
        uint8_t ck_prime[16], ik_prime[16];
        SwuAkaPrimeKeys keys;
        swu_aka_prime_ckik(ck, ik, network_name, autn, ck_prime, ik_prime);
        swu_aka_prime_keys(ck_prime, ik_prime, cfg_.identity, keys);
        k_aut.assign(keys.k_aut, keys.k_aut + 32);
        msk.assign(keys.msk, keys.msk + 64);
    } else {
        SwuAkaKeys keys;
        swu_aka_keys(ck, ik, cfg_.identity, keys);
        k_aut.assign(keys.k_aut, keys.k_aut + 16);
        msk.assign(keys.msk, keys.msk + 64);
    }

    /* AT_MAC covers the whole packet with the MAC field zeroed
     * (RFC 4187 §10.15, RFC 5448 §3.4) */
    SwuBytes zeroed(eap);
    memset(&zeroed[mac_off], 0, 16);
    if (CRYPTO_memcmp(aka_mac(prime, k_aut, zeroed).data(), &eap[mac_off], 16) != 0) {
        fail("AT_MAC of the EAP-AKA challenge does not verify (identity or network name differ)");
        return false;
    }
    msk_ = msk;

    put8(reply, EAP_RESPONSE);
    put8(reply, eap[1]);
    put16(reply, 40);
    put8(reply, eap[4]);
    put8(reply, AKA_CHALLENGE);
    put16(reply, 0);
    put8(reply, AT_RES);
    put8(reply, 3);
    put16(reply, 64);       /* RES length in bits */
    put(reply, res, 8);
    put8(reply, AT_MAC);
    put8(reply, 5);
    put16(reply, 0);
    reply.resize(40, 0);
    SwuBytes mac = aka_mac(prime, k_aut, reply);
    memcpy(&reply[24], mac.data(), 16);
    return true;
}

void SwuSession::finish_auth(const std::vector<Payload> &pls)
{
    bool authenticated = false;
    char addr[INET_ADDRSTRLEN];

    for (size_t i = 0; i < pls.size(); i++) {
        const SwuBytes &b = pls[i].body;
        if (pls[i].type == PL_AUTH && b.size() == 4 + 32 && b[0] == 2 && !idr_body_.empty()) {
            static const char pad[] = "Key Pad for IKEv2";
            SwuBytes key = hmac256(msk_, (const uint8_t *)pad, sizeof(pad) - 1);
            SwuBytes expect = hmac256(key, auth_octets(false));
            authenticated = CRYPTO_memcmp(expect.data(), b.data() + 4, 32) == 0;
        } else if (pls[i].type == PL_CP && b.size() >= 4 && b[0] == 2 /* CFG_REPLY */) {
            for (size_t off = 4; off + 4 <= b.size();) {
                uint16_t type = get16(&b[off]) & 0x7fff;
                size_t alen = get16(&b[off + 2]);
                if (off + 4 + alen > b.size()) {
                    break;
                }
                bool v4 = type == 1 || type == 20 || type == 16389;
                bool v6 = type == 8 || type == 21 || type == 16390;
                char addr6[INET6_ADDRSTRLEN];
                if (v4 && alen >= 4 && inet_ntop(AF_INET, &b[off + 4], addr, sizeof(addr))) {
                    if (type == 1 && inner_ip_.empty()) {
                        inner_ip_ = addr;
                    } else if (type != 1 && pcscf_.empty()) {
                        /* RFC 7651, or the 3GPP private attribute */
                        pcscf_ = addr;
                    }
                } else if (v6 && alen >= 16 && inet_ntop(AF_INET6, &b[off + 4], addr6, sizeof(addr6))) {
                    /* INTERNAL_IP6_ADDRESS: address and prefix length; the
                     * address is the UE's (prefix and interface identifier
                     * from the PGW) */
                    if (type == 8 && inner_ip6_.empty()) {
                        inner_ip6_ = addr6;
                    } else if (type != 8 && pcscf6_.empty()) {
                        pcscf6_ = addr6;
                    }
                }
                off += 4 + alen;
            }
        } else if (pls[i].type == PL_SA && b.size() >= 12 && b[5] == 3 && b[6] == 4) {
            child_spi_r_ = get32(&b[8]);
        }
    }

    if (!authenticated) {
        fail("ePDG did not prove knowledge of the MSK (AUTH missing or wrong)");
        return;
    }
    if ((inner_ip_.empty() && inner_ip6_.empty()) || !child_spi_r_) {
        fail("ePDG assigned no inner address or no ESP SA");
        return;
    }
    {
        /* SIP uses IPv6 when there is an inner IPv6 address and a P-CSCF
         * for it (GSMA IR.92 prefers IPv6), unless the scenario says which */
        bool can6 = !inner_ip6_.empty(), can4 = !inner_ip_.empty();
        bool use6 = cfg_.sip_family == 6 ? can6 :
                    cfg_.sip_family == 4 ? !can4 :
                    (can6 && !pcscf6_.empty()) || !can4;
        sip_ip_ = use6 ? inner_ip6_ : inner_ip_;
        sip_pcscf_ = use6 ? pcscf6_ : pcscf_;
    }
    if (install_kernel() < 0) {
        fail("cannot install the tunnel in the kernel (CAP_NET_ADMIN?)");
        return;
    }
    state_ = SWU_ESTABLISHED;
    LOG_MSG("SWu %s: tunnel up (asked for %s), inner IP %s%s%s, P-CSCF %s%s%s, SIP from %s\n", cfg_.identity.c_str(),
            cfg_.pdn_type == 2 ? "IPv6" : cfg_.pdn_type == 3 ? "IPv4v6" : "IPv4",
            inner_ip_.c_str(), !inner_ip_.empty() && !inner_ip6_.empty() ? " and " : "",
            inner_ip6_.c_str(), pcscf_.empty() && pcscf6_.empty() ? "(none)" : pcscf_.c_str(),
            !pcscf_.empty() && !pcscf6_.empty() ? " and " : "", pcscf6_.c_str(), sip_ip_.c_str());
}

int SwuSession::install_kernel()
{
    /* RFC 7296 §2.17: initiator-to-responder keys come first */
    SwuBytes nonces(nonce_i_);
    put(nonces, nonce_r_);
    SwuBytes km = swu_prf_plus(sk_d_, nonces, 4 * 32);
    const uint8_t *ei = km.data(), *ai = ei + 32, *er = ai + 32, *ar = er + 32;
    const char *local = outer_local_.c_str(), *epdg = cfg_.epdg.c_str();

    if (xfrm_init() < 0) {
        return -1;
    }
    reqid_ = next_reqid++;
    XfrmTunnel tun = { local, epdg, reqid_ };

    if (xfrm_add_tunnel_sa(local, epdg, child_spi_r_, reqid_, outer_port_, IKE_NATT_PORT,
                           ei, 256, ai, 256) < 0) {
        return -1;
    }
    sa_out_ = true;
    if (xfrm_add_tunnel_sa(epdg, local, child_spi_i_, reqid_, IKE_NATT_PORT, outer_port_,
                           er, 256, ar, 256) < 0) {
        return -1;
    }
    sa_in_ = true;
    /* One pair of policies and one local address per inner address; both
     * families share the SA pair (IPv6 in an IPv4 tunnel, RFC 7296 §2.9) */
    if (!inner_ip_.empty()) {
        if (xfrm_add_tunnel_policy(inner_ip_.c_str(), XFRM_POLICY_OUT, &tun) < 0) {
            return -1;
        }
        pol_out_ = true;
        if (xfrm_add_tunnel_policy(inner_ip_.c_str(), XFRM_POLICY_IN, &tun) < 0) {
            return -1;
        }
        pol_in_ = true;
        if (inner_addr(inner_ip_.c_str(), true) < 0) {
            return -1;
        }
        addr_ = true;
    }
    if (!inner_ip6_.empty()) {
        if (xfrm_add_tunnel_policy(inner_ip6_.c_str(), XFRM_POLICY_OUT, &tun) < 0) {
            return -1;
        }
        pol6_out_ = true;
        if (xfrm_add_tunnel_policy(inner_ip6_.c_str(), XFRM_POLICY_IN, &tun) < 0) {
            return -1;
        }
        pol6_in_ = true;
        if (inner_addr(inner_ip6_.c_str(), true) < 0) {
            WARNING("SWu: cannot add the inner IPv6 address %s to %s (IPv6 disabled?)",
                    inner_ip6_.c_str(), SWU_INNER_DEV);
            return -1;
        }
        addr6_ = true;
        enable_ipv6_on_outer(outer_local_);
        inner6_route(true);
        inner6_rule(inner_ip6_.c_str(), false);     /* left by a run that crashed */
        if (inner6_rule(inner_ip6_.c_str(), true) < 0) {
            WARNING("SWu: cannot add the routing rule for the inner IPv6 address %s", inner_ip6_.c_str());
            return -1;
        }
    }
    return 0;
}

void SwuSession::remove_kernel()
{
    const char *local = outer_local_.c_str(), *epdg = cfg_.epdg.c_str();

    if (addr_) {
        inner_addr(inner_ip_.c_str(), false);
    }
    if (pol_out_) {
        xfrm_del_tunnel_policy(inner_ip_.c_str(), XFRM_POLICY_OUT);
    }
    if (pol_in_) {
        xfrm_del_tunnel_policy(inner_ip_.c_str(), XFRM_POLICY_IN);
    }
    if (addr6_) {
        inner6_rule(inner_ip6_.c_str(), false);
        inner_addr(inner_ip6_.c_str(), false);
    }
    if (pol6_out_) {
        xfrm_del_tunnel_policy(inner_ip6_.c_str(), XFRM_POLICY_OUT);
    }
    if (pol6_in_) {
        xfrm_del_tunnel_policy(inner_ip6_.c_str(), XFRM_POLICY_IN);
    }
    if (sa_out_) {
        xfrm_del_sa(local, epdg, child_spi_r_, 0);
    }
    if (sa_in_) {
        xfrm_del_sa(epdg, local, child_spi_i_, 0);
    }
    addr_ = pol_out_ = pol_in_ = sa_out_ = sa_in_ = false;
    addr6_ = pol6_out_ = pol6_in_ = false;
}

void SwuSession::detach()
{
    if (state_ != SWU_ESTABLISHED) {
        return;
    }
    std::vector<Payload> pls(1);
    pls[0].type = PL_DELETE;
    put8(pls[0].body, 1);   /* the IKE SA, and with it the child SA */
    put8(pls[0].body, 0);
    put16(pls[0].body, 0);
    state_ = SWU_DELETING;
    send_request(EXCH_INFORMATIONAL, pls, true);
}

void SwuSession::on_request(uint8_t exchange, uint32_t msgid, uint8_t first,
                            const uint8_t *msg, size_t len)
{
    if (msgid == last_peer_msgid_ && !last_peer_reply_.empty()) {
        transmit(last_peer_reply_);     /* our answer was lost */
        return;
    }
    std::vector<Payload> pls, reply;
    if (!decrypt(first, msg, len, pls)) {
        return;
    }

    bool deleted = false;
    if (exchange == EXCH_INFORMATIONAL) {
        /* Empty = dead peer detection; Delete = the ePDG ends the tunnel */
        for (size_t i = 0; i < pls.size(); i++) {
            deleted = deleted || pls[i].type == PL_DELETE;
        }
    } else {
        /* CREATE_CHILD_SA: rekeying is not supported */
        Payload p;
        p.type = PL_NOTIFY;
        p.body = notify_body(N_NO_ADDITIONAL_SAS);
        reply.push_back(p);
    }
    last_peer_msgid_ = msgid;
    last_peer_reply_ = build_msg(exchange, FLAG_INITIATOR | FLAG_RESPONSE, msgid, reply, true);
    transmit(last_peer_reply_);

    if (deleted) {
        WARNING("SWu %s: tunnel deleted by the ePDG", cfg_.identity.c_str());
        error_ = "tunnel deleted by the ePDG";
        set_pending(false);
        remove_kernel();
        state_ = SWU_CLOSED;
    }
}

void SwuSession::poll_all()
{
    if (all_sessions.empty()) {
        return;
    }
    struct epoll_event ev[64];
    int n;
    do {
        n = epoll_wait(swu_epfd, ev, 64, 0);
        for (int i = 0; i < n; i++) {
            ((SwuSession *)ev[i].data.ptr)->on_readable();
        }
    } while (n == 64);

    if (!pending_sessions.empty()) {
        std::vector<SwuSession *> waiting(pending_sessions.begin(), pending_sessions.end());
        for (size_t i = 0; i < waiting.size(); i++) {
            waiting[i]->on_timer();
        }
    }
}

void SwuSession::shutdown_all()
{
    for (std::set<SwuSession *>::iterator it = all_sessions.begin(); it != all_sessions.end(); ++it) {
        SwuSession *s = *it;
        if (s->state_ == SWU_ESTABLISHED) {
            std::vector<Payload> pls(1);
            pls[0].type = PL_DELETE;
            put8(pls[0].body, 1);
            put8(pls[0].body, 0);
            put16(pls[0].body, 0);
            s->transmit(s->build_msg(EXCH_INFORMATIONAL, FLAG_INITIATOR, s->next_msgid_, pls, true));
            s->state_ = SWU_CLOSED;
        }
        s->remove_kernel();
    }
    /* The route of inner6_route(); there is none if no session had IPv6 */
    inner6_route(false);
}

#ifdef GTEST
#include "gtest/gtest.h"

static SwuBytes unhex(const char *hex)
{
    SwuBytes out;
    for (; hex[0] && hex[1]; hex += 2) {
        unsigned int byte;
        sscanf(hex, "%2x", &byte);
        out.push_back(byte);
    }
    return out;
}

/* RFC 5448 Appendix C: both cases share RAND, AUTN, CK and IK and differ only
 * in the access network name. */
static void aka_prime_vector(const char *network_name, uint8_t ck_prime[16],
                             uint8_t ik_prime[16], SwuAkaPrimeKeys &keys)
{
    SwuBytes autn = unhex("bb52e91c747ac3ab2a5c23d15ee351d5");
    SwuBytes ik = unhex("9744871ad32bf9bbd1dd5ce54e3e2e5a");
    SwuBytes ck = unhex("5349fbe098649f948f5d2e973a81c00f");
    swu_aka_prime_ckik(ck.data(), ik.data(), network_name, autn.data(), ck_prime, ik_prime);
    swu_aka_prime_keys(ck_prime, ik_prime, "0555444333222111", keys);
}

/* The AAA server derives K_aut and the MSK on its own: unless ours are
 * bit-identical, AT_MAC fails and the ePDG rejects our IKE AUTH payload. */
TEST(Swu, AkaPrimeKeysMatchRfc5448Case1) {
    uint8_t ck_prime[16], ik_prime[16];
    SwuAkaPrimeKeys keys;
    aka_prime_vector("WLAN", ck_prime, ik_prime, keys);

    EXPECT_EQ(unhex("0093962d0dd84aa5684b045c9edffa04"), SwuBytes(ck_prime, ck_prime + 16));
    EXPECT_EQ(unhex("ccfc230ca74fcc96c0a5d61164f5a76c"), SwuBytes(ik_prime, ik_prime + 16));
    EXPECT_EQ(unhex("766fa0a6c317174b812d52fbcd11a179"), SwuBytes(keys.k_encr, keys.k_encr + 16));
    EXPECT_EQ(unhex("0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea"),
              SwuBytes(keys.k_aut, keys.k_aut + 32));
    EXPECT_EQ(unhex("cf83aa8bc7e0aced892acc98e76a9b2095b558c7795c7094715cb3393aa7d17a"),
              SwuBytes(keys.k_re, keys.k_re + 32));
    EXPECT_EQ(unhex("67c42d9aa56c1b79e295e3459fc3d187d42be0bf818d3070e362c5e967a4d544"
                    "e8ecfe19358ab3039aff03b7c930588c055babee58a02650b067ec4e9347c75a"),
              SwuBytes(keys.msk, keys.msk + 64));
    EXPECT_EQ(unhex("f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c"
                    "313f69924bdd7650ca9bac141ea075c4ef9e8029c0e290cdbad5638b63bc23fb"),
              SwuBytes(keys.emsk, keys.emsk + 64));
}

/* The point of AKA' over AKA: keys are bound to the access network name, so
 * a vector issued for one network is useless in another. */
TEST(Swu, AkaPrimeKeysAreBoundToNetworkName) {
    uint8_t ck_prime[16], ik_prime[16];
    SwuAkaPrimeKeys keys;
    aka_prime_vector("HRPD", ck_prime, ik_prime, keys);

    EXPECT_EQ(unhex("3820f0277fa5f77732b1fb1d90c1a0da"), SwuBytes(ck_prime, ck_prime + 16));
    EXPECT_EQ(unhex("db94a0ab557ef6c9ab48619ca05b9a9f"), SwuBytes(ik_prime, ik_prime + 16));
    EXPECT_EQ(unhex("5b4acaef62c6ebb8882b2f3d534c4b35277337a00184f20ff25d224c04be2afd"),
              SwuBytes(keys.k_aut, keys.k_aut + 32));
    EXPECT_EQ(unhex("87b321570117cd6c95ab6c436fb5073ff15cf85505d2bc5bb7355fc21ea8a757"
                    "57e8f86a2b138002e05752913bb43b82f868a96117e91a2d95f526677d572900"),
              SwuBytes(keys.msk, keys.msk + 64));
}

/* EAP-AKA uses the FIPS 186-2 generator, for which RFC 4186 A.5 gives the
 * only published vector. A wrong K_aut or MSK fails AT_MAC or IKE AUTH. */
TEST(Swu, Fips186PrfMatchesRfc4186) {
    SwuBytes mk = unhex("e576d5ca332e9930018bf1baee2763c795b3c712");
    uint8_t out[160];
    swu_fips186_prf(mk.data(), out, sizeof(out));

    EXPECT_EQ(unhex("536e5ebc4465582aa6a8ec9986ebb620"), SwuBytes(out, out + 16));
    EXPECT_EQ(unhex("25af1942efcbf4bc72b3943421f2a974"), SwuBytes(out + 16, out + 32));
    EXPECT_EQ(unhex("39d45aeaf4e30601983e972b6cfd46d1c363773365690d09cd44976b525f47d3"
                    "a60a985e955c53b090b2e4b73719196a402542968fd14a888f46b9a7886e4488"),
              SwuBytes(out + 32, out + 96));
    EXPECT_EQ(unhex("5949eab0fff69d52315c6c634fd14a7f0d52023d56f79698fa6596abeed4f93f"
                    "bb48eb534d985414ceed0d9a8ed33c387c9dfdab92ffbdf240fcecf65a2c93b9"),
              SwuBytes(out + 96, out + 160));
}

/* prf+ feeds every IKE and ESP key: T1 = prf(K, S | 0x01), each further
 * block chains the previous one (RFC 7296 §2.13). */
TEST(Swu, PrfPlusChainsBlocks) {
    SwuBytes key = unhex("000102030405060708090a0b0c0d0e0f");
    SwuBytes seed = unhex("a0a1a2a3");

    SwuBytes in1(seed);
    in1.push_back(1);
    SwuBytes t1 = hmac256(key, in1);
    SwuBytes in2(t1);
    in2.insert(in2.end(), seed.begin(), seed.end());
    in2.push_back(2);
    SwuBytes t2 = hmac256(key, in2);

    SwuBytes out = swu_prf_plus(key, seed, 40);
    ASSERT_EQ(40u, out.size());
    EXPECT_EQ(t1, SwuBytes(out.begin(), out.begin() + 32));
    EXPECT_EQ(SwuBytes(t2.begin(), t2.begin() + 8), SwuBytes(out.begin() + 32, out.end()));
}
#endif /* GTEST */

#endif /* USE_SWU */
