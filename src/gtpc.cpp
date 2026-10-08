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
 *  S8 control plane (GTPv2-C, 3GPP TS 29.274) for S8 home-routed roaming
 *  tests: SIPp plays the visited SGW toward the home PGW.
 *
 *  What a real visited network does and this does not: there is no S11
 *  (MME and SGW are one), no S1-U and no NAS, so bearer requests from the
 *  PGW are answered at once instead of after the radio bearer is set up,
 *  and the location (ULI), serving network and equipment identity are
 *  whatever the scenario says. IPv4 PDN connections only.
 */

#ifdef USE_S8

#include "gtpc.hpp"
#include "gtpu.hpp"
#include "sipp.hpp"

#include <cctype>
#include <cstdarg>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <map>
#include <set>

#include <unistd.h>
#include <sys/time.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

/* Message types (TS 29.274 Table 6.1-1) */
enum {
    GTP_ECHO_REQUEST = 1, GTP_ECHO_RESPONSE = 2,
    GTP_CREATE_SESSION_REQUEST = 32, GTP_CREATE_SESSION_RESPONSE = 33,
    GTP_DELETE_SESSION_REQUEST = 36, GTP_DELETE_SESSION_RESPONSE = 37,
    GTP_CREATE_BEARER_REQUEST = 95, GTP_CREATE_BEARER_RESPONSE = 96,
    GTP_UPDATE_BEARER_REQUEST = 97, GTP_UPDATE_BEARER_RESPONSE = 98,
    GTP_DELETE_BEARER_REQUEST = 99, GTP_DELETE_BEARER_RESPONSE = 100,
    GTPC_PORT = 2123
};

/* Information element types (TS 29.274 Table 8.1-1), with their clause */
enum {
    IE_IMSI = 1,                /* §8.3 */
    IE_CAUSE = 2,               /* §8.4 */
    IE_RECOVERY = 3,            /* §8.5 */
    IE_APN = 71,                /* §8.6 */
    IE_AMBR = 72,               /* §8.7 */
    IE_EBI = 73,                /* §8.8 */
    IE_MEI = 75,                /* §8.10 */
    IE_MSISDN = 76,             /* §8.11 */
    IE_PCO = 78,                /* §8.13 */
    IE_PAA = 79,                /* §8.14 */
    IE_BEARER_QOS = 80,         /* §8.15 */
    IE_BEARER_TFT = 84,         /* §8.19 */
    IE_RAT_TYPE = 82,           /* §8.17 */
    IE_SERVING_NETWORK = 83,    /* §8.18 */
    IE_ULI = 86,                /* §8.21 */
    IE_FTEID = 87,              /* §8.22 */
    IE_BEARER_CONTEXT = 93,     /* §8.28 */
    IE_PDN_TYPE = 99,           /* §8.34 */
    IE_APN_RESTRICTION = 127,   /* §8.57 */
    IE_SELECTION_MODE = 128     /* §8.58 */
};

/* F-TEID interface types (§8.22) */
enum {
    FTEID_S5S8_SGW_GTPU = 4, FTEID_S5S8_PGW_GTPU = 5,
    FTEID_S5S8_SGW_GTPC = 6, FTEID_S5S8_PGW_GTPC = 7
};

enum {
    RAT_EUTRAN = 6,             /* §8.17 */
    PDN_TYPE_IPV4 = 1,          /* §8.34 */
    PDN_TYPE_IPV6 = 2,
    PDN_TYPE_IPV4V6 = 3,
    DEFAULT_EBI = 5,
    MAX_EBI = 15,               /* §8.8: EBI is 4 bits, 5..15 in EPS */
    /* PCO protocol/container ids (TS 24.008 §10.5.6.3) */
    PCO_PCSCF_IPV6 = 0x0001,
    PCO_IM_CN_SIGNALLING_FLAG = 0x0002,
    PCO_DNS_IPV6 = 0x0003,
    PCO_PCSCF_IPV4 = 0x000c,
    PCO_DNS_IPV4 = 0x000d
};

/* --- byte helpers ------------------------------------------------------- */

static void put8(GtpBytes &b, uint8_t v) { b.push_back(v); }
static void put16(GtpBytes &b, uint16_t v) { b.push_back(v >> 8); b.push_back(v & 0xff); }
static void put32(GtpBytes &b, uint32_t v) { put16(b, v >> 16); put16(b, v & 0xffff); }
static void put(GtpBytes &b, const GtpBytes &o) { b.insert(b.end(), o.begin(), o.end()); }
static uint16_t get16(const uint8_t *p) { return (p[0] << 8) | p[1]; }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)get16(p) << 16) | get16(p + 2); }

static void put_ie(GtpBytes &b, uint8_t type, uint8_t instance, const GtpBytes &value)
{
    put8(b, type);
    put16(b, value.size());
    put8(b, instance & 0x0f);
    put(b, value);
}

static void put_ie8(GtpBytes &b, uint8_t type, uint8_t instance, uint8_t value)
{
    put_ie(b, type, instance, GtpBytes(1, value));
}

GtpBytes gtp_tbcd(const std::string &digits)
{
    GtpBytes out;
    std::string d;
    for (size_t i = 0; i < digits.size(); i++) {
        if (isdigit((unsigned char)digits[i])) {
            d += digits[i];
        }
    }
    for (size_t i = 0; i < d.size(); i += 2) {
        uint8_t low = d[i] - '0';
        uint8_t high = i + 1 < d.size() ? d[i + 1] - '0' : 0x0f;
        out.push_back((high << 4) | low);
    }
    return out;
}

bool gtp_plmn(const std::string &mccmnc, uint8_t out[3])
{
    if (mccmnc.size() != 5 && mccmnc.size() != 6) {
        return false;
    }
    for (size_t i = 0; i < mccmnc.size(); i++) {
        if (!isdigit((unsigned char)mccmnc[i])) {
            return false;
        }
    }
    const char *d = mccmnc.c_str();
    uint8_t mnc3 = mccmnc.size() == 6 ? d[5] - '0' : 0x0f;
    out[0] = ((d[1] - '0') << 4) | (d[0] - '0');
    out[1] = (mnc3 << 4) | (d[2] - '0');
    out[2] = ((d[4] - '0') << 4) | (d[3] - '0');
    return true;
}

GtpBytes gtp_apn(const std::string &apn)
{
    GtpBytes out;
    size_t start = 0;
    while (start <= apn.size()) {
        size_t dot = apn.find('.', start);
        if (dot == std::string::npos) {
            dot = apn.size();
        }
        put8(out, dot - start);
        out.insert(out.end(), apn.begin() + start, apn.begin() + dot);
        start = dot + 1;
    }
    return out;
}

static GtpBytes fteid(uint8_t iface, uint32_t teid, const std::string &ip)
{
    GtpBytes v;
    struct in_addr a;
    memset(&a, 0, sizeof(a));
    inet_pton(AF_INET, ip.c_str(), &a);
    put8(v, 0x80 | iface);      /* V4 present */
    put32(v, teid);
    v.insert(v.end(), (uint8_t *)&a, (uint8_t *)&a + 4);
    return v;
}

static GtpBytes message(uint8_t type, bool with_teid, uint32_t teid, uint32_t seq,
                        const GtpBytes &ies)
{
    /* §5.1: version 2; T set when a TEID follows; length counts everything
     * after the first four octets */
    GtpBytes m;
    put8(m, with_teid ? 0x48 : 0x40);
    put8(m, type);
    put16(m, (with_teid ? 8 : 4) + ies.size());
    if (with_teid) {
        put32(m, teid);
    }
    put8(m, seq >> 16);
    put8(m, seq >> 8);
    put8(m, seq);
    put8(m, 0);
    put(m, ies);
    return m;
}

GtpBytes gtp_encode_create_session(const S8Config &cfg, uint32_t seq,
                                   uint32_t c_teid, uint32_t u_teid, uint8_t recovery)
{
    /* Create Session Request on S5/S8, TS 29.274 Table 7.2.1-1 */
    GtpBytes ies, v;
    uint8_t plmn[3] = { 0, 0, 0 };
    gtp_plmn(cfg.plmn, plmn);

    put_ie(ies, IE_IMSI, 0, gtp_tbcd(cfg.imsi));
    if (!cfg.msisdn.empty()) {
        put_ie(ies, IE_MSISDN, 0, gtp_tbcd(cfg.msisdn));
    }
    if (!cfg.mei.empty()) {
        put_ie(ies, IE_MEI, 0, gtp_tbcd(cfg.mei));
    }

    /* ULI with TAI and ECGI (§8.21.4, §8.21.5) */
    v.clear();
    put8(v, 0x18);
    v.insert(v.end(), plmn, plmn + 3);
    put16(v, cfg.tac);
    v.insert(v.end(), plmn, plmn + 3);
    put32(v, cfg.eci & 0x0fffffff);
    put_ie(ies, IE_ULI, 0, v);

    put_ie(ies, IE_SERVING_NETWORK, 0, GtpBytes(plmn, plmn + 3));
    put_ie8(ies, IE_RAT_TYPE, 0, RAT_EUTRAN);
    put_ie(ies, IE_FTEID, 0, fteid(FTEID_S5S8_SGW_GTPC, c_teid, cfg.local_ip));
    put_ie(ies, IE_APN, 0, gtp_apn(cfg.apn));
    put_ie8(ies, IE_SELECTION_MODE, 0, 0);      /* subscribed APN, verified */
    int pdn = cfg.pdn_type == PDN_TYPE_IPV6 || cfg.pdn_type == PDN_TYPE_IPV4V6 ? cfg.pdn_type
                                                                               : PDN_TYPE_IPV4;
    bool want4 = pdn != PDN_TYPE_IPV6, want6 = pdn != PDN_TYPE_IPV4;
    put_ie8(ies, IE_PDN_TYPE, 0, pdn);

    /* PAA (§8.14), all zero to have the PGW allocate: the type, then for
     * IPv6 the prefix length and prefix, then for IPv4 the address */
    v.assign(1 + (want6 ? 17 : 0) + (want4 ? 4 : 0), 0);
    v[0] = pdn;
    put_ie(ies, IE_PAA, 0, v);

    put_ie8(ies, IE_APN_RESTRICTION, 0, 0);     /* maximum APN restriction: none */

    v.clear();
    put32(v, cfg.ambr_ul);
    put32(v, cfg.ambr_dl);
    put_ie(ies, IE_AMBR, 0, v);

    /* PCO: ask for the P-CSCF and DNS addresses and flag the bearer as the
     * IMS signalling bearer, as a VoLTE UE does (TS 24.008 §10.5.6.3) */
    v.clear();
    put8(v, 0x80);
    static const uint16_t containers[] = { PCO_PCSCF_IPV6, PCO_DNS_IPV6, PCO_PCSCF_IPV4,
                                           PCO_DNS_IPV4, PCO_IM_CN_SIGNALLING_FLAG };
    for (size_t i = 0; i < sizeof(containers) / sizeof(containers[0]); i++) {
        bool v6 = containers[i] == PCO_PCSCF_IPV6 || containers[i] == PCO_DNS_IPV6;
        bool v4 = containers[i] == PCO_PCSCF_IPV4 || containers[i] == PCO_DNS_IPV4;
        if ((v6 && !want6) || (v4 && !want4)) {
            continue;
        }
        put16(v, containers[i]);
        put8(v, 0);
    }
    put_ie(ies, IE_PCO, 0, v);

    /* Bearer context to be created: the default bearer (§7.2.1-2) */
    GtpBytes bc, qos;
    put_ie8(bc, IE_EBI, 0, DEFAULT_EBI);
    put_ie(bc, IE_FTEID, 2, fteid(FTEID_S5S8_SGW_GTPU, u_teid, cfg.local_ip));
    /* Bearer QoS (§8.15): ARP (no pre-emption capability, pre-emptable:
     * PCI = 1, PVI = 0), QCI, then MBR and GBR, zero for a non-GBR bearer */
    put8(qos, 0x40 | ((cfg.arp & 0x0f) << 2));
    put8(qos, cfg.qci);
    qos.resize(22, 0);
    put_ie(bc, IE_BEARER_QOS, 0, qos);
    put_ie(ies, IE_BEARER_CONTEXT, 0, bc);

    put_ie8(ies, IE_RECOVERY, 0, recovery);

    return message(GTP_CREATE_SESSION_REQUEST, true, 0, seq, ies);
}

/* Call fn(type, instance, value, len) for each IE; false on a broken TLV */
template <typename F>
static bool for_each_ie(const uint8_t *p, size_t len, F fn)
{
    size_t off = 0;
    while (off < len) {
        if (off + 4 > len) {
            return false;
        }
        size_t vlen = get16(p + off + 1);
        if (off + 4 + vlen > len) {
            return false;
        }
        fn(p[off], p[off + 3] & 0x0f, p + off + 4, vlen);
        off += 4 + vlen;
    }
    return true;
}

struct Header {
    uint8_t type;
    bool has_teid;
    uint32_t teid;
    uint32_t seq;
    const uint8_t *ies;
    size_t ies_len;
};

static bool decode_header(const uint8_t *msg, size_t len, Header &h)
{
    if (len < 8 || (msg[0] >> 5) != 2) {
        return false;
    }
    size_t total = 4 + (size_t)get16(msg + 2);
    h.has_teid = (msg[0] & 0x08) != 0;
    size_t hdr = h.has_teid ? 12 : 8;
    if (total > len || total < hdr) {
        return false;
    }
    h.type = msg[1];
    h.teid = h.has_teid ? get32(msg + 4) : 0;
    const uint8_t *s = msg + (h.has_teid ? 8 : 4);
    h.seq = ((uint32_t)s[0] << 16) | (s[1] << 8) | s[2];
    h.ies = msg + hdr;
    h.ies_len = total - hdr;
    return true;
}

static std::string ip4(const uint8_t *p)
{
    char buf[INET_ADDRSTRLEN];
    return inet_ntop(AF_INET, p, buf, sizeof(buf)) ? buf : "";
}

static std::string ip6(const uint8_t *p)
{
    char buf[INET6_ADDRSTRLEN];
    return inet_ntop(AF_INET6, p, buf, sizeof(buf)) ? buf : "";
}

struct FteidOut {
    uint8_t iface;
    std::string *ip;
    uint32_t *teid;
};

static void take_fteid(const uint8_t *v, size_t len, const FteidOut &want)
{
    if (len >= 9 && (v[0] & 0x80) && (v[0] & 0x3f) == want.iface) {
        *want.teid = get32(v + 1);
        *want.ip = ip4(v + 5);
    }
}

bool gtp_decode_create_session_response(const uint8_t *msg, size_t len, S8Result &out)
{
    /* Create Session Response, TS 29.274 Table 7.2.2-1 */
    Header h;
    if (!decode_header(msg, len, h) || h.type != GTP_CREATE_SESSION_RESPONSE) {
        return false;
    }
    out = S8Result();
    out.pgw_c_teid = out.pgw_u_teid = 0;
    out.pdn_type = 0;
    S8Result *r = &out;
    return for_each_ie(h.ies, h.ies_len, [r](uint8_t type, uint8_t, const uint8_t *v, size_t vlen) {
        if (type == IE_CAUSE && vlen >= 1) {
            r->cause = v[0];
        } else if (type == IE_FTEID) {
            FteidOut want = { FTEID_S5S8_PGW_GTPC, &r->pgw_c_ip, &r->pgw_c_teid };
            take_fteid(v, vlen, want);
        } else if (type == IE_PAA && vlen >= 5 && (v[0] & 0x07) == PDN_TYPE_IPV4) {
            r->pdn_type = PDN_TYPE_IPV4;
            r->ue_ip = ip4(v + 1);
        } else if (type == IE_PAA && vlen >= 18 && ((v[0] & 0x07) == PDN_TYPE_IPV6 ||
                                                    (v[0] & 0x07) == PDN_TYPE_IPV4V6)) {
            /* Prefix length, then prefix and interface identifier: the /64
             * is the UE's, the identifier is what the PGW expects in its
             * link-local address and is used for the global one here too */
            r->pdn_type = v[0] & 0x07;
            r->ue_ip6 = ip6(v + 2);
            if (r->pdn_type == PDN_TYPE_IPV4V6 && vlen >= 22) {
                r->ue_ip = ip4(v + 18);
            }
        } else if (type == IE_PCO && vlen >= 1) {
            /* containers after the configuration protocol octet */
            for (size_t off = 1; off + 3 <= vlen;) {
                uint16_t id = get16(v + off);
                size_t clen = v[off + 2];
                if (off + 3 + clen > vlen) {
                    break;
                }
                if (id == PCO_PCSCF_IPV4 && clen == 4 && r->pcscf.empty()) {
                    r->pcscf = ip4(v + off + 3);
                } else if (id == PCO_PCSCF_IPV6 && clen == 16 && r->pcscf6.empty()) {
                    r->pcscf6 = ip6(v + off + 3);
                }
                off += 3 + clen;
            }
        } else if (type == IE_BEARER_CONTEXT) {
            for_each_ie(v, vlen, [r](uint8_t t, uint8_t, const uint8_t *bv, size_t blen) {
                if (t == IE_FTEID) {
                    FteidOut want = { FTEID_S5S8_PGW_GTPU, &r->pgw_u_ip, &r->pgw_u_teid };
                    take_fteid(bv, blen, want);
                }
            });
        }
    });
}

/* --- dedicated bearers: codec ------------------------------------------- */

/* Packet filter component type identifiers (TS 24.008 Table 10.5.162) */
enum {
    PF_IPV4_REMOTE = 0x10, PF_IPV4_LOCAL = 0x11,
    PF_IPV6_REMOTE = 0x20, PF_IPV6_REMOTE_PREFIX = 0x21, PF_IPV6_LOCAL_PREFIX = 0x23,
    PF_PROTOCOL = 0x30,
    PF_LOCAL_PORT = 0x40, PF_LOCAL_PORT_RANGE = 0x41,
    PF_REMOTE_PORT = 0x50, PF_REMOTE_PORT_RANGE = 0x51,
    PF_SPI = 0x60, PF_TOS = 0x70, PF_FLOW_LABEL = 0x80
};

/* Contents of one packet filter. A component this user plane cannot
 * evaluate (SPI, TOS, flow label, unknown) makes the filter select
 * nothing, so such traffic stays on the default bearer. */
static void decode_filter_contents(const uint8_t *c, size_t len, GtpuFilter &f)
{
    size_t off = 0;
    while (off < len) {
        uint8_t type = c[off++];
        size_t left = len - off;
        if ((type == PF_IPV4_REMOTE || type == PF_IPV4_LOCAL) && left >= 8) {
            uint32_t *addr = type == PF_IPV4_REMOTE ? &f.remote_addr : &f.local_addr;
            uint32_t *mask = type == PF_IPV4_REMOTE ? &f.remote_mask : &f.local_mask;
            memcpy(addr, c + off, 4);
            memcpy(mask, c + off + 4, 4);
            off += 8;
        } else if ((type == PF_IPV6_REMOTE_PREFIX || type == PF_IPV6_LOCAL_PREFIX) && left >= 17) {
            /* Address and prefix length */
            bool remote = type == PF_IPV6_REMOTE_PREFIX;
            memcpy(remote ? f.remote6 : f.local6, c + off, 16);
            (remote ? f.remote6_len : f.local6_len) = c[off + 16] > 128 ? 128 : c[off + 16];
            off += 17;
        } else if (type == PF_IPV6_REMOTE && left >= 32) {
            /* Address and mask: the mask's leading one bits are the prefix */
            int bits = 0;
            while (bits < 128 && (c[off + 16 + bits / 8] & (0x80 >> (bits % 8)))) {
                bits++;
            }
            memcpy(f.remote6, c + off, 16);
            f.remote6_len = bits;
            off += 32;
        } else if (type == PF_PROTOCOL && left >= 1) {
            f.protocol = c[off];
            off += 1;
        } else if ((type == PF_LOCAL_PORT || type == PF_REMOTE_PORT) && left >= 2) {
            uint16_t port = get16(c + off);
            if (type == PF_LOCAL_PORT) {
                f.local_port_lo = f.local_port_hi = port;
            } else {
                f.remote_port_lo = f.remote_port_hi = port;
            }
            off += 2;
        } else if ((type == PF_LOCAL_PORT_RANGE || type == PF_REMOTE_PORT_RANGE) && left >= 4) {
            if (type == PF_LOCAL_PORT_RANGE) {
                f.local_port_lo = get16(c + off);
                f.local_port_hi = get16(c + off + 2);
            } else {
                f.remote_port_lo = get16(c + off);
                f.remote_port_hi = get16(c + off + 2);
            }
            off += 4;
        } else {
            /* The length of an unknown component is unknown too: stop here */
            f.never = true;
            return;
        }
    }
}

bool gtp_decode_tft(const uint8_t *v, size_t len, int &opcode,
                    std::vector<GtpTftFilter> &filters)
{
    filters.clear();
    if (len < 1) {
        return false;
    }
    /* Octet 1: operation code (3 bits), E bit, number of packet filters */
    opcode = v[0] >> 5;
    size_t count = v[0] & 0x0f;
    size_t off = 1;

    if (opcode == TFT_DELETE_FILTERS) {
        /* A list of packet filter identifiers */
        if (off + count > len) {
            return false;
        }
        for (size_t i = 0; i < count; i++) {
            GtpTftFilter f;
            f.id = v[off + i] & 0x0f;
            f.direction = 0;
            filters.push_back(f);
        }
        return true;
    }
    if (opcode != TFT_CREATE && opcode != TFT_ADD_FILTERS && opcode != TFT_REPLACE_FILTERS) {
        return opcode == TFT_DELETE || opcode == TFT_NO_OPERATION;
    }
    for (size_t i = 0; i < count; i++) {
        /* Identifier and direction, evaluation precedence, length, contents */
        if (off + 3 > len || off + 3 + v[off + 2] > len) {
            return false;
        }
        GtpTftFilter f;
        f.id = v[off] & 0x0f;
        f.direction = (v[off] >> 4) & 0x03;
        f.match.precedence = v[off + 1];
        decode_filter_contents(v + off + 3, v[off + 2], f.match);
        filters.push_back(f);
        off += 3 + v[off + 2];
    }
    return true;
}

void gtp_apply_tft(std::vector<GtpTftFilter> &current, int opcode,
                   const std::vector<GtpTftFilter> &filters)
{
    if (opcode == TFT_CREATE || opcode == TFT_DELETE) {
        current.clear();
    }
    if (opcode == TFT_NO_OPERATION || opcode == TFT_DELETE) {
        return;
    }
    for (size_t i = 0; i < filters.size(); i++) {
        for (size_t k = 0; k < current.size(); k++) {
            if (current[k].id == filters[i].id) {
                current.erase(current.begin() + k);
                break;
            }
        }
        if (opcode != TFT_DELETE_FILTERS) {
            current.push_back(filters[i]);
        }
    }
}

std::vector<GtpuFilter> gtp_uplink_filters(const std::vector<GtpTftFilter> &tft)
{
    std::vector<GtpuFilter> out;
    for (size_t i = 0; i < tft.size(); i++) {
        /* Direction 0 is a filter of a pre Rel-7 network, valid both ways */
        if (tft[i].direction != 1) {
            out.push_back(tft[i].match);
        }
    }
    return out;
}

bool gtp_decode_bearer_request(const uint8_t *ies, size_t len, int &linked_ebi,
                               std::vector<GtpBearerRequest> &bearers)
{
    linked_ebi = 0;
    bearers.clear();
    int *lbi = &linked_ebi;
    std::vector<GtpBearerRequest> *out = &bearers;
    return for_each_ie(ies, len, [lbi, out](uint8_t type, uint8_t inst, const uint8_t *v, size_t vlen) {
        if (type == IE_EBI && inst == 0 && vlen >= 1) {
            *lbi = v[0] & 0x0f;
        } else if (type == IE_BEARER_CONTEXT && inst == 0) {
            GtpBearerRequest b;
            b.ebi = b.qci = 0;
            b.has_tft = false;
            b.tft_ok = true;
            b.tft_opcode = TFT_NO_OPERATION;
            b.pgw_u_teid = 0;
            GtpBearerRequest *bp = &b;
            for_each_ie(v, vlen, [bp](uint8_t t, uint8_t, const uint8_t *bv, size_t blen) {
                if (t == IE_EBI && blen >= 1) {
                    bp->ebi = bv[0] & 0x0f;
                } else if (t == IE_BEARER_TFT) {
                    bp->has_tft = true;
                    bp->tft_ok = gtp_decode_tft(bv, blen, bp->tft_opcode, bp->tft);
                } else if (t == IE_FTEID) {
                    /* S5/S8-U PGW F-TEID: where our uplink goes */
                    FteidOut want = { FTEID_S5S8_PGW_GTPU, &bp->pgw_u_ip, &bp->pgw_u_teid };
                    take_fteid(bv, blen, want);
                } else if (t == IE_BEARER_QOS && blen >= 2) {
                    bp->qci = bv[1];
                }
            });
            out->push_back(b);
        }
    });
}

/* --- endpoint ----------------------------------------------------------- */

/* One GTPv2-C entity for the process (the "SGW"): one socket, one sequence
 * number space, and the maps that route what the PGW sends to a session. */
class GtpcEndpoint {
public:
    static bool open(std::string &error);
    static void send_to_pgw(const GtpBytes &msg);
    static void send_to(const GtpBytes &msg, const struct sockaddr_in &to);
    static void receive();

    static int fd;
    static struct sockaddr_in pgw;
    static uint32_t next_seq;
    static uint32_t next_teid;
    static uint8_t recovery;
    static std::set<S8Session *> all;
    static std::map<uint32_t, S8Session *> by_seq;      /* our pending requests */
    static std::map<uint32_t, S8Session *> by_teid;     /* our control TEIDs */
};

int GtpcEndpoint::fd = -1;
struct sockaddr_in GtpcEndpoint::pgw;
uint32_t GtpcEndpoint::next_seq = 1;
uint32_t GtpcEndpoint::next_teid = 0;
uint8_t GtpcEndpoint::recovery = 0;
std::set<S8Session *> GtpcEndpoint::all;
std::map<uint32_t, S8Session *> GtpcEndpoint::by_seq;
std::map<uint32_t, S8Session *> GtpcEndpoint::by_teid;

bool GtpcEndpoint::open(std::string &error)
{
    if (fd >= 0) {
        return true;
    }
    if (!s8_pgw) {
        error = "no PGW given (-s8_pgw)";
        return false;
    }
    /* host[:port] */
    std::string host(s8_pgw), port("2123");
    size_t colon = host.rfind(':');
    if (colon != std::string::npos) {
        port = host.substr(colon + 1);
        host.resize(colon);
    }
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        error = "cannot resolve the PGW '" + host + "' (IPv4 only)";
        return false;
    }
    memcpy(&pgw, res->ai_addr, sizeof(pgw));
    freeaddrinfo(res);

    /* The PGW addresses its own requests (Create Bearer, ...) to port 2123 of
     * the address in our F-TEID, so requests and responses share a socket
     * bound there. */
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(GTPC_PORT);
    const char *bind_ip = s8_local_ip ? s8_local_ip : local_ip;
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (s < 0 || inet_pton(AF_INET, bind_ip, &local.sin_addr) != 1 ||
        bind(s, (struct sockaddr *)&local, sizeof(local)) < 0) {
        error = std::string("cannot bind GTP-C to ") + bind_ip + ":2123: " + strerror(errno);
        if (s >= 0) {
            close(s);
        }
        return false;
    }
    fd = s;
    /* Restart counter: has to change when we restart, so the PGW drops the
     * sessions of the previous run (§7.1.1). Seconds are good enough. */
    recovery = (uint8_t)time(nullptr);
    /* A peer answers a request whose sequence number it has seen from this
     * address and port in the last seconds with the response it gave then
     * (§7.6). Counting from 1 in every process made a PGW answer the Create
     * Session Request of a run with the response of the run before it. */
    struct timeval tv;
    gettimeofday(&tv, nullptr);
    next_seq = (((uint32_t)tv.tv_sec * 1000003u + (uint32_t)tv.tv_usec) ^ ((uint32_t)getpid() << 9)) & 0x7fffff;
    if (next_seq == 0) {
        next_seq = 1;
    }
    next_teid = 0x20000000u | ((uint32_t)(getpid() & 0xfff) << 16) | 1;
    return true;
}

void GtpcEndpoint::send_to(const GtpBytes &msg, const struct sockaddr_in &to)
{
    if (fd >= 0 && sendto(fd, msg.data(), msg.size(), 0,
                          (const struct sockaddr *)&to, sizeof(to)) < 0) {
        WARNING("S8: GTP-C send failed: %s", strerror(errno));
    }
}

void GtpcEndpoint::send_to_pgw(const GtpBytes &msg)
{
    send_to(msg, pgw);
}

void GtpcEndpoint::receive()
{
    uint8_t buf[8192];
    for (int i = 0; i < 64; i++) {
        struct sockaddr_in from;
        socklen_t flen = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &flen);
        if (n <= 0) {
            return;
        }
        Header h;
        if (!decode_header(buf, n, h)) {
            continue;
        }
        switch (h.type) {
        case GTP_ECHO_REQUEST: {
            GtpBytes ies;
            put_ie8(ies, IE_RECOVERY, 0, recovery);
            send_to(message(GTP_ECHO_RESPONSE, false, 0, h.seq, ies), from);
            break;
        }
        case GTP_ECHO_RESPONSE:
            break;
        case GTP_CREATE_SESSION_RESPONSE:
        case GTP_DELETE_SESSION_RESPONSE: {
            /* A response belongs to the request with its sequence number (§7.6) */
            std::map<uint32_t, S8Session *>::iterator it = by_seq.find(h.seq);
            if (it != by_seq.end()) {
                it->second->on_response(h.type, buf, n);
            }
            break;
        }
        default: {
            /* A request of the PGW, addressed to one of our control TEIDs */
            std::map<uint32_t, S8Session *>::iterator it = by_teid.find(h.teid);
            if (it != by_teid.end()) {
                it->second->on_request(h.type, h.seq, h.ies, h.ies_len, from);
            } else if (h.type == GTP_CREATE_BEARER_REQUEST ||
                       h.type == GTP_UPDATE_BEARER_REQUEST ||
                       h.type == GTP_DELETE_BEARER_REQUEST) {
                GtpBytes ies;
                GtpBytes cause(2, 0);
                cause[0] = GTP_CAUSE_CONTEXT_NOT_FOUND;
                put_ie(ies, IE_CAUSE, 0, cause);
                send_to(message(h.type + 1, true, 0, h.seq, ies), from);
            }
        }
        }
    }
}

/* --- session ------------------------------------------------------------ */

S8Session::S8Session(const S8Config &cfg) :
    cfg_(cfg), state_(S8_IDLE), c_teid_(0), u_teid_(0), user_plane_(false),
    pending_seq_(0), retrans_at_(0), retrans_count_(0)
{
    result_ = S8Result();
    result_.pgw_c_teid = result_.pgw_u_teid = 0;
    result_.pdn_type = 0;
    GtpcEndpoint::all.insert(this);
}

S8Session::~S8Session()
{
    if (state_ == S8_ACTIVE) {
        /* Best effort: the owner is going away and cannot wait for the answer. */
        GtpBytes ies;
        put_ie8(ies, IE_EBI, 0, DEFAULT_EBI);
        GtpcEndpoint::send_to_pgw(message(GTP_DELETE_SESSION_REQUEST, true, result_.pgw_c_teid,
                                          GtpcEndpoint::next_seq++ & 0xffffff, ies));
    }
    release_user_plane();
    if (pending_seq_) {
        GtpcEndpoint::by_seq.erase(pending_seq_);
    }
    if (c_teid_) {
        GtpcEndpoint::by_teid.erase(c_teid_);
    }
    GtpcEndpoint::all.erase(this);
}

void S8Session::fail(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    error_ = buf;
    WARNING("S8 %s: %s", cfg_.imsi.c_str(), buf);
    state_ = S8_FAILED;
    if (pending_seq_) {
        GtpcEndpoint::by_seq.erase(pending_seq_);
        pending_seq_ = 0;
    }
    pending_.clear();
    release_user_plane();
}

void S8Session::release_user_plane()
{
    while (!bearers_.empty()) {
        drop_bearer(bearers_.size() - 1, "released with the session");
    }
    if (user_plane_) {
        gtpu_del_ue(ue_key());
        user_plane_ = false;
    }
}

void S8Session::send_request(uint8_t type, uint32_t teid, const GtpBytes &ies)
{
    /* §7.6: a sequence number of our own per request; the same message is
     * retransmitted every T3-RESPONSE, N3-REQUESTS times in all. */
    pending_seq_ = GtpcEndpoint::next_seq++ & 0xffffff;
    if (pending_seq_ == 0) {
        pending_seq_ = GtpcEndpoint::next_seq++ & 0xffffff;
    }
    pending_ = message(type, true, teid, pending_seq_, ies);
    GtpcEndpoint::by_seq[pending_seq_] = this;
    retrans_count_ = 0;
    retrans_at_ = clock_tick + s8_t3;
    GtpcEndpoint::send_to_pgw(pending_);
}

int S8Session::create()
{
    uint8_t plmn[3];
    if (!GtpcEndpoint::open(error_)) {
        fail("%s", std::string(error_).c_str());
        return -1;
    }
    if (cfg_.local_ip.empty()) {
        cfg_.local_ip = s8_local_ip ? s8_local_ip : local_ip;
    }
    if (gtpu_start(cfg_.local_ip.c_str()) < 0) {
        fail("user plane: %s", gtpu_error());
        return -1;
    }
    if (!gtp_plmn(cfg_.plmn, plmn)) {
        fail("visited PLMN '%s' is not <mcc><mnc> (-visited_plmn)", cfg_.plmn.c_str());
        return -1;
    }
    c_teid_ = GtpcEndpoint::next_teid++;
    u_teid_ = gtpu_new_teid();
    GtpcEndpoint::by_teid[c_teid_] = this;

    /* The request carries TEID 0: the PGW has no context yet (§5.5.1) */
    pending_seq_ = GtpcEndpoint::next_seq++ & 0xffffff;
    if (pending_seq_ == 0) {
        pending_seq_ = GtpcEndpoint::next_seq++ & 0xffffff;
    }
    pending_ = gtp_encode_create_session(cfg_, pending_seq_, c_teid_, u_teid_,
                                         GtpcEndpoint::recovery);
    GtpcEndpoint::by_seq[pending_seq_] = this;
    retrans_count_ = 0;
    retrans_at_ = clock_tick + s8_t3;
    state_ = S8_CREATING;
    GtpcEndpoint::send_to_pgw(pending_);
    return 0;
}

void S8Session::remove()
{
    if (state_ != S8_ACTIVE) {
        return;
    }
    /* Delete Session Request (Table 7.2.9.1-1): the linked EBI names the
     * default bearer, and with it the whole PDN connection */
    GtpBytes ies;
    put_ie8(ies, IE_EBI, 0, DEFAULT_EBI);
    state_ = S8_DELETING;
    send_request(GTP_DELETE_SESSION_REQUEST, result_.pgw_c_teid, ies);
}

void S8Session::on_response(uint8_t type, const uint8_t *msg, size_t len)
{
    GtpcEndpoint::by_seq.erase(pending_seq_);
    pending_seq_ = 0;
    pending_.clear();

    if (state_ == S8_CREATING && type == GTP_CREATE_SESSION_RESPONSE) {
        if (!gtp_decode_create_session_response(msg, len, result_)) {
            fail("malformed Create Session Response");
            return;
        }
        if (result_.cause < GTP_CAUSE_ACCEPTED || result_.cause > GTP_CAUSE_ACCEPTED_LAST) {
            int cause = result_.cause;
            fail("Create Session rejected by the PGW, cause %d", cause);
            result_.cause = cause;
            return;
        }
        if ((result_.ue_ip.empty() && result_.ue_ip6.empty()) || !result_.pgw_u_teid ||
            result_.pgw_u_ip.empty()) {
            fail("Create Session Response without UE address or PGW user plane F-TEID");
            return;
        }
        /* SIP uses IPv6 when the UE has an IPv6 address and the PGW named
         * a P-CSCF for it (GSMA IR.92: IPv6 is preferred), unless the
         * scenario asks for one family */
        {
            bool can6 = !result_.ue_ip6.empty(), can4 = !result_.ue_ip.empty();
            bool use6 = cfg_.sip_family == 6 ? can6 :
                        cfg_.sip_family == 4 ? !can4 :
                        (can6 && !result_.pcscf6.empty()) || !can4;
            result_.sip_ip = use6 ? result_.ue_ip6 : result_.ue_ip;
            result_.sip_pcscf = use6 ? result_.pcscf6 : result_.pcscf;
        }
        if (gtpu_add_ue(result_.ue_ip.c_str(), result_.ue_ip6.c_str(), u_teid_, result_.pgw_u_ip.c_str(),
                        result_.pgw_u_teid) < 0) {
            fail("user plane: %s", gtpu_error());
            return;
        }
        user_plane_ = true;
        state_ = S8_ACTIVE;
        LOG_MSG("S8 %s: session up, UE IP %s%s%s, P-CSCF %s%s%s, SIP from %s, PGW-U %s TEID 0x%x\n",
                cfg_.imsi.c_str(), result_.ue_ip.c_str(),
                !result_.ue_ip.empty() && !result_.ue_ip6.empty() ? " and " : "",
                result_.ue_ip6.c_str(),
                result_.pcscf.empty() && result_.pcscf6.empty() ? "(none)" : result_.pcscf.c_str(),
                !result_.pcscf.empty() && !result_.pcscf6.empty() ? " and " : "",
                result_.pcscf6.c_str(), result_.sip_ip.c_str(),
                result_.pgw_u_ip.c_str(), result_.pgw_u_teid);
    } else if (state_ == S8_DELETING && type == GTP_DELETE_SESSION_RESPONSE) {
        Header h;
        int *cause = &result_.cause;
        if (decode_header(msg, len, h)) {
            for_each_ie(h.ies, h.ies_len, [cause](uint8_t t, uint8_t, const uint8_t *v, size_t vlen) {
                if (t == IE_CAUSE && vlen >= 1) {
                    *cause = v[0];
                }
            });
        }
        release_user_plane();
        state_ = S8_CLOSED;
    }
}

/* Bearer context of a response: EBI, cause, and for a created bearer both
 * user plane F-TEIDs */
static GtpBytes bearer_answer(int ebi, int bearer_cause, const GtpBytes &fteids = GtpBytes())
{
    GtpBytes bc, cause(2, 0);
    cause[0] = bearer_cause;
    put_ie8(bc, IE_EBI, 0, ebi);
    put_ie(bc, IE_CAUSE, 0, cause);
    put(bc, fteids);
    return bc;
}

static GtpBytes with_cause(int message_cause, const GtpBytes &rest)
{
    GtpBytes out, cause(2, 0);
    cause[0] = message_cause;
    put_ie(out, IE_CAUSE, 0, cause);
    put(out, rest);
    return out;
}

/* Wall clock for the bearer log lines, to line them up with a capture */
static std::string log_time()
{
    struct timeval tv;
    char buf[32], out[48];
    gettimeofday(&tv, nullptr);
    time_t t = tv.tv_sec;
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(buf, sizeof(buf), "%H:%M:%S", &tm);
    snprintf(out, sizeof(out), "%s.%03d", buf, (int)(tv.tv_usec / 1000));
    return out;
}

/* One packet filter as a line for the log */
static std::string describe_filter(const GtpTftFilter &f)
{
    static const char *dir[] = { "both ways (pre Rel-7)", "downlink", "uplink", "both ways" };
    char buf[320], local[INET6_ADDRSTRLEN + 8] = "any", remote[INET6_ADDRSTRLEN + 8] = "any";
    const GtpuFilter &m = f.match;
    if (m.local_mask) {
        inet_ntop(AF_INET, &m.local_addr, local, sizeof(local));
    } else if (m.local6_len >= 0) {
        inet_ntop(AF_INET6, m.local6, local, INET6_ADDRSTRLEN);
        snprintf(local + strlen(local), 8, "/%d", m.local6_len);
    }
    if (m.remote_mask) {
        inet_ntop(AF_INET, &m.remote_addr, remote, sizeof(remote));
    } else if (m.remote6_len >= 0) {
        inet_ntop(AF_INET6, m.remote6, remote, INET6_ADDRSTRLEN);
        snprintf(remote + strlen(remote), 8, "/%d", m.remote6_len);
    }
    snprintf(buf, sizeof(buf), "filter %d %s, precedence %d: protocol %d, local %s port %d-%d, remote %s port %d-%d%s",
             f.id, dir[f.direction & 3], m.precedence, m.protocol, local, m.local_port_lo,
             m.local_port_hi, remote, m.remote_port_lo, m.remote_port_hi,
             m.never ? " (has a component SIPp cannot evaluate: selects nothing)" : "");
    return buf;
}

static void log_filters(const std::string &imsi, const S8Bearer &b)
{
    for (size_t i = 0; i < b.tft.size(); i++) {
        LOG_MSG("S8 %s: EBI %d %s\n", imsi.c_str(), b.ebi, describe_filter(b.tft[i]).c_str());
    }
}

int S8Session::dedicated_bearer(int qci) const
{
    for (size_t i = 0; i < bearers_.size(); i++) {
        if (qci == 0 || bearers_[i].qci == qci) {
            return bearers_[i].ebi;
        }
    }
    return 0;
}

void S8Session::drop_bearer(size_t index, const char *why)
{
    const S8Bearer &b = bearers_[index];
    unsigned long ul = 0, dl = 0;
    gtpu_bearer_counters(ue_key(), b.ebi, ul, dl);
    LOG_MSG("%s S8 %s: dedicated bearer EBI %d (QCI %d) %s, carried %lu uplink and %lu downlink packets\n",
            log_time().c_str(), cfg_.imsi.c_str(), b.ebi, b.qci, why, ul, dl);
    gtpu_del_bearer(ue_key(), b.ebi);
    bearers_.erase(bearers_.begin() + index);
}

/*
 * Create Bearer Request (Table 7.2.3-1). An SGW would ask the MME, which
 * assigns the EBI after the UE and the eNodeB accepted; there is neither
 * here, so every bearer is accepted at once with the lowest free EBI.
 * Response per Table 7.2.4-1: on S5/S8 the bearer context carries the SGW's
 * F-TEID (instance 2) and echoes the PGW's (instance 3), by which the PGW
 * tells the bearers of one request apart.
 */
GtpBytes S8Session::create_bearers(const uint8_t *ies, size_t len)
{
    int lbi = 0;
    std::vector<GtpBearerRequest> wanted;
    if (!gtp_decode_bearer_request(ies, len, lbi, wanted) || wanted.empty()) {
        return with_cause(GTP_CAUSE_REQUEST_REJECTED, GtpBytes());
    }
    GtpBytes contexts;
    bool any_ok = false;
    for (size_t i = 0; i < wanted.size(); i++) {
        const GtpBearerRequest &w = wanted[i];
        S8Bearer b;
        b.ebi = 0;
        for (int ebi = DEFAULT_EBI + 1; ebi <= MAX_EBI && !b.ebi; ebi++) {
            bool used = false;
            for (size_t k = 0; k < bearers_.size(); k++) {
                used = used || bearers_[k].ebi == ebi;
            }
            if (!used) {
                b.ebi = ebi;
            }
        }
        GtpBytes fteids;
        if (!w.pgw_u_ip.empty()) {
            put_ie(fteids, IE_FTEID, 3, fteid(FTEID_S5S8_PGW_GTPU, w.pgw_u_teid, w.pgw_u_ip));
        }
        if (!b.ebi || w.pgw_u_ip.empty() || !w.tft_ok) {
            put_ie(contexts, IE_BEARER_CONTEXT, 0,
                   bearer_answer(0, !b.ebi ? GTP_CAUSE_NO_RESOURCES : GTP_CAUSE_REQUEST_REJECTED,
                                 fteids));
            continue;
        }
        b.qci = w.qci;
        b.pgw_u_ip = w.pgw_u_ip;
        b.pgw_u_teid = w.pgw_u_teid;
        b.local_teid = gtpu_new_teid();
        gtp_apply_tft(b.tft, w.tft_opcode, w.tft);
        if (gtpu_add_bearer(ue_key(), b.ebi, b.local_teid, b.pgw_u_ip.c_str(),
                            b.pgw_u_teid, gtp_uplink_filters(b.tft)) < 0) {
            put_ie(contexts, IE_BEARER_CONTEXT, 0,
                   bearer_answer(0, GTP_CAUSE_REQUEST_REJECTED, fteids));
            continue;
        }
        bearers_.push_back(b);
        any_ok = true;
        GtpBytes both;
        put_ie(both, IE_FTEID, 2, fteid(FTEID_S5S8_SGW_GTPU, b.local_teid, cfg_.local_ip));
        put(both, fteids);
        put_ie(contexts, IE_BEARER_CONTEXT, 0, bearer_answer(b.ebi, GTP_CAUSE_ACCEPTED, both));
        LOG_MSG("%s S8 %s: dedicated bearer EBI %d (QCI %d) created, %zu packet filters, "
                "PGW-U %s TEID 0x%x, local TEID 0x%x\n",
                log_time().c_str(), cfg_.imsi.c_str(), b.ebi, b.qci, b.tft.size(), b.pgw_u_ip.c_str(),
                b.pgw_u_teid, b.local_teid);
        log_filters(cfg_.imsi, b);
    }
    return with_cause(any_ok ? GTP_CAUSE_ACCEPTED : GTP_CAUSE_REQUEST_REJECTED, contexts);
}

/* Update Bearer Request (Table 7.2.15-1): a new TFT or QoS for bearers that
 * exist. Response per Table 7.2.16-1. */
GtpBytes S8Session::update_bearers(const uint8_t *ies, size_t len)
{
    int lbi = 0;
    std::vector<GtpBearerRequest> wanted;
    if (!gtp_decode_bearer_request(ies, len, lbi, wanted)) {
        return with_cause(GTP_CAUSE_REQUEST_REJECTED, GtpBytes());
    }
    GtpBytes contexts;
    bool unknown = false;
    for (size_t i = 0; i < wanted.size(); i++) {
        const GtpBearerRequest &w = wanted[i];
        int bearer_cause = GTP_CAUSE_ACCEPTED;
        S8Bearer *b = nullptr;
        for (size_t k = 0; k < bearers_.size(); k++) {
            if (bearers_[k].ebi == w.ebi) {
                b = &bearers_[k];
            }
        }
        if (b && !w.tft_ok) {
            bearer_cause = GTP_CAUSE_REQUEST_REJECTED;
        } else if (b) {
            if (w.has_tft) {
                gtp_apply_tft(b->tft, w.tft_opcode, w.tft);
                gtpu_set_filters(ue_key(), b->ebi, gtp_uplink_filters(b->tft));
            }
            if (w.qci) {
                b->qci = w.qci;
            }
            LOG_MSG("%s S8 %s: dedicated bearer EBI %d updated, QCI %d, %zu packet filters\n",
                    log_time().c_str(), cfg_.imsi.c_str(), b->ebi, b->qci, b->tft.size());
            log_filters(cfg_.imsi, *b);
        } else if (w.ebi != DEFAULT_EBI) {
            /* The default bearer has no uplink filters to keep here; its
             * QoS and APN-AMBR are not enforced */
            bearer_cause = GTP_CAUSE_CONTEXT_NOT_FOUND;
            unknown = true;
        }
        put_ie(contexts, IE_BEARER_CONTEXT, 0, bearer_answer(w.ebi, bearer_cause));
    }
    return with_cause(unknown ? GTP_CAUSE_CONTEXT_NOT_FOUND : GTP_CAUSE_ACCEPTED, contexts);
}

/* Delete Bearer Request (Table 7.2.9.2-1): either the linked EBI (instance
 * 0), which ends the PDN connection, or the EBIs of dedicated bearers
 * (instance 1). Response per Table 7.2.10.2-1. */
GtpBytes S8Session::delete_bearers(const uint8_t *ies, size_t len, bool &session_deleted)
{
    GtpBytes rest;
    std::vector<int> ebis;
    GtpBytes *o = &rest;
    bool *del = &session_deleted;
    std::vector<int> *e = &ebis;
    for_each_ie(ies, len, [o, del, e](uint8_t t, uint8_t inst, const uint8_t *v, size_t vlen) {
        if (t == IE_EBI && vlen >= 1 && inst == 0) {
            put_ie8(*o, IE_EBI, 0, v[0]);
            *del = true;
        } else if (t == IE_EBI && vlen >= 1) {
            e->push_back(v[0] & 0x0f);
        }
    });
    for (size_t i = 0; i < ebis.size(); i++) {
        int bearer_cause = GTP_CAUSE_CONTEXT_NOT_FOUND;
        for (size_t k = 0; k < bearers_.size(); k++) {
            if (bearers_[k].ebi == ebis[i]) {
                drop_bearer(k, "deleted by the PGW");
                bearer_cause = GTP_CAUSE_ACCEPTED;
                break;
            }
        }
        put_ie(rest, IE_BEARER_CONTEXT, 0, bearer_answer(ebis[i], bearer_cause));
    }
    return with_cause(GTP_CAUSE_ACCEPTED, rest);
}

void S8Session::on_request(uint8_t type, uint32_t seq, const uint8_t *ies, size_t len,
                           const struct sockaddr_in &from)
{
    bool deleted = false;

    if (type != GTP_CREATE_BEARER_REQUEST && type != GTP_UPDATE_BEARER_REQUEST &&
        type != GTP_DELETE_BEARER_REQUEST) {
        return;
    }
    std::map<uint32_t, GtpBytes>::iterator again = answered_.find(seq);
    if (again != answered_.end() && again->second.size() > 1 && again->second[1] == type + 1) {
        GtpcEndpoint::send_to(again->second, from);
        return;
    }
    GtpBytes out;
    if (state_ != S8_ACTIVE) {
        out = with_cause(GTP_CAUSE_CONTEXT_NOT_FOUND, GtpBytes());
    } else if (type == GTP_CREATE_BEARER_REQUEST) {
        out = create_bearers(ies, len);
    } else if (type == GTP_UPDATE_BEARER_REQUEST) {
        out = update_bearers(ies, len);
    } else {
        out = delete_bearers(ies, len, deleted);
    }
    GtpBytes answer = message(type + 1, true, result_.pgw_c_teid, seq, out);
    if (answered_.size() >= 16) {
        answered_.erase(answered_.begin());
    }
    answered_[seq] = answer;
    GtpcEndpoint::send_to(answer, from);

    if (deleted && state_ == S8_ACTIVE) {
        WARNING("S8 %s: PDN connection deleted by the PGW", cfg_.imsi.c_str());
        error_ = "PDN connection deleted by the PGW";
        release_user_plane();
        state_ = S8_CLOSED;
    }
}

void S8Session::on_timer()
{
    if (pending_.empty() || clock_tick < retrans_at_) {
        return;
    }
    if (retrans_count_ >= s8_n3) {
        if (state_ == S8_DELETING) {
            GtpcEndpoint::by_seq.erase(pending_seq_);
            pending_seq_ = 0;
            pending_.clear();
            release_user_plane();
            result_.cause = -1;
            state_ = S8_CLOSED;
        } else {
            fail("no answer from the PGW %s", s8_pgw);
            result_.cause = -1;
        }
        return;
    }
    retrans_count_++;
    retrans_at_ = clock_tick + s8_t3;
    GtpcEndpoint::send_to_pgw(pending_);
}

void S8Session::poll_all()
{
    if (GtpcEndpoint::fd < 0) {
        return;
    }
    GtpcEndpoint::receive();
    if (!GtpcEndpoint::by_seq.empty()) {
        std::vector<S8Session *> waiting;
        for (std::map<uint32_t, S8Session *>::iterator it = GtpcEndpoint::by_seq.begin();
             it != GtpcEndpoint::by_seq.end(); ++it) {
            waiting.push_back(it->second);
        }
        for (size_t i = 0; i < waiting.size(); i++) {
            if (GtpcEndpoint::all.count(waiting[i])) {
                waiting[i]->on_timer();
            }
        }
    }
}

void S8Session::shutdown_all()
{
    for (std::set<S8Session *>::iterator it = GtpcEndpoint::all.begin();
         it != GtpcEndpoint::all.end(); ++it) {
        S8Session *s = *it;
        if (s->state_ == S8_ACTIVE) {
            GtpBytes ies;
            put_ie8(ies, IE_EBI, 0, DEFAULT_EBI);
            GtpcEndpoint::send_to_pgw(message(GTP_DELETE_SESSION_REQUEST, true,
                                              s->result_.pgw_c_teid,
                                              GtpcEndpoint::next_seq++ & 0xffffff, ies));
            s->state_ = S8_CLOSED;
        }
        s->user_plane_ = false;     /* gtpu_stop() removes everything at once */
    }
    gtpu_stop();
}

#ifdef GTEST
#include "gtest/gtest.h"

static GtpBytes bytes(const char *hex)
{
    GtpBytes out;
    for (; hex[0] && hex[1]; hex += 2) {
        unsigned int byte;
        sscanf(hex, "%2x", &byte);
        out.push_back(byte);
    }
    return out;
}

/* IMSI and MSISDN are how the PGW, the PCRF and charging identify the
 * subscriber: one swapped nibble is another subscriber. */
TEST(Gtpc, TbcdSwapsDigitPairsAndFillsOddLength) {
    EXPECT_EQ(bytes("62220400009900f1"), gtp_tbcd("262240000099001"));
    EXPECT_EQ(bytes("945155009900f1"), gtp_tbcd("+4915550099001"));
}

/* The serving network decides roaming policy and charging at the PGW. The
 * third MNC digit sits in the middle octet, 0xF when the MNC has two. */
TEST(Gtpc, PlmnEncodingHandlesBothMncLengths) {
    uint8_t p[3];
    ASSERT_TRUE(gtp_plmn("26224", p));
    EXPECT_EQ(bytes("62f242"), GtpBytes(p, p + 3));
    ASSERT_TRUE(gtp_plmn("310410", p));
    EXPECT_EQ(bytes("130014"), GtpBytes(p, p + 3));
    EXPECT_FALSE(gtp_plmn("2622", p));
    EXPECT_FALSE(gtp_plmn("262x4", p));
}

TEST(Gtpc, ApnIsEncodedAsLabels) {
    EXPECT_EQ(bytes("03696d73"), gtp_apn("ims"));
    EXPECT_EQ(bytes("03696d73066d6e63303234"), gtp_apn("ims.mnc024"));
}

static S8Config test_config()
{
    S8Config c;
    c.imsi = "262240000099001";
    c.msisdn = "+4915550099001";
    c.apn = "ims";
    c.plmn = "00101";
    c.local_ip = "10.13.13.2";
    c.qci = 5;
    c.arp = 9;
    c.ambr_ul = 1000;
    c.ambr_dl = 2000;
    c.tac = 1;
    c.eci = 0x15ee001;
    c.pdn_type = 1;
    c.sip_family = 0;
    return c;
}

/* Open5GS rejects a Create Session Request for E-UTRAN that lacks the
 * serving network, the ULI, the sender F-TEID, a bearer context with EBI and
 * QoS, the S5/S8-U SGW F-TEID or the PAA. Walk the message as the PGW would
 * and check that every one of them is there, with the right interface types
 * and instances (TS 29.274 Table 7.2.1-1). */
TEST(Gtpc, CreateSessionRequestCarriesWhatThePgwRequires) {
    GtpBytes msg = gtp_encode_create_session(test_config(), 0x000102, 0x11111111, 0x22222222, 7);
    Header h;
    ASSERT_TRUE(decode_header(msg.data(), msg.size(), h));
    EXPECT_EQ(GTP_CREATE_SESSION_REQUEST, h.type);
    EXPECT_TRUE(h.has_teid);
    EXPECT_EQ(0u, h.teid);          /* the PGW has no context yet */
    EXPECT_EQ(0x000102u, h.seq);
    EXPECT_EQ(msg.size(), 4u + get16(msg.data() + 2));

    std::map<int, GtpBytes> top, bearer;
    ASSERT_TRUE(for_each_ie(h.ies, h.ies_len, [&](uint8_t t, uint8_t inst, const uint8_t *v, size_t n) {
        top[t * 16 + inst] = GtpBytes(v, v + n);
    }));
    EXPECT_EQ(bytes("62220400009900f1"), top[IE_IMSI * 16]);
    EXPECT_EQ(bytes("00f110"), top[IE_SERVING_NETWORK * 16]);
    EXPECT_EQ(GtpBytes(1, RAT_EUTRAN), top[IE_RAT_TYPE * 16]);
    /* TAI then ECGI, each with the PLMN */
    EXPECT_EQ(bytes("18" "00f110" "0001" "00f110" "015ee001"), top[IE_ULI * 16]);
    /* sender F-TEID: IPv4, S5/S8 SGW GTP-C, our TEID and address */
    EXPECT_EQ(bytes("86" "11111111" "0a0d0d02"), top[IE_FTEID * 16]);
    EXPECT_EQ(bytes("01" "00000000"), top[IE_PAA * 16]);
    EXPECT_EQ(bytes("000003e8" "000007d0"), top[IE_AMBR * 16]);

    const GtpBytes &bc = top[IE_BEARER_CONTEXT * 16];
    ASSERT_FALSE(bc.empty());
    ASSERT_TRUE(for_each_ie(bc.data(), bc.size(), [&](uint8_t t, uint8_t inst, const uint8_t *v, size_t n) {
        bearer[t * 16 + inst] = GtpBytes(v, v + n);
    }));
    EXPECT_EQ(GtpBytes(1, 5), bearer[IE_EBI * 16]);
    /* S5/S8-U SGW F-TEID is instance 2 inside the bearer context */
    EXPECT_EQ(bytes("84" "22222222" "0a0d0d02"), bearer[IE_FTEID * 16 + 2]);
    ASSERT_EQ(22u, bearer[IE_BEARER_QOS * 16].size());
    EXPECT_EQ(0x40 | (9 << 2), bearer[IE_BEARER_QOS * 16][0]);
    EXPECT_EQ(5, bearer[IE_BEARER_QOS * 16][1]);
}

/* What the call needs afterwards comes from four different IEs: the UE's
 * address (PAA), where to send GTP-C and GTP-U (two F-TEIDs told apart only
 * by interface type) and the P-CSCF (a PCO container). */
TEST(Gtpc, CreateSessionResponseYieldsAddressesAndTeids) {
    GtpBytes ies, v, bc, cause = bytes("1000");
    put_ie(ies, IE_CAUSE, 0, cause);
    put_ie(ies, IE_FTEID, 1, bytes("87" "0000beef" "0a00010a"));
    put_ie(ies, IE_PAA, 0, bytes("01" "0a2e0005"));
    put_ie(ies, IE_PCO, 0, bytes("80" "000d04" "08080808" "000c04" "2ee1c599" "000c04" "2ee1c59a"));
    put_ie8(bc, IE_EBI, 0, 5);
    put_ie(bc, IE_CAUSE, 0, cause);
    put_ie(bc, IE_FTEID, 2, bytes("85" "0000cafe" "0a000102"));
    put_ie(ies, IE_BEARER_CONTEXT, 0, bc);
    GtpBytes msg = message(GTP_CREATE_SESSION_RESPONSE, true, 0x11111111, 5, ies);

    S8Result r;
    ASSERT_TRUE(gtp_decode_create_session_response(msg.data(), msg.size(), r));
    EXPECT_EQ(GTP_CAUSE_ACCEPTED, r.cause);
    EXPECT_EQ("10.46.0.5", r.ue_ip);
    EXPECT_EQ("46.225.197.153", r.pcscf);       /* the first one offered */
    EXPECT_EQ("10.0.1.10", r.pgw_c_ip);
    EXPECT_EQ(0xbeefu, r.pgw_c_teid);
    EXPECT_EQ("10.0.1.2", r.pgw_u_ip);
    EXPECT_EQ(0xcafeu, r.pgw_u_teid);
}

/* A rejection has to surface as its cause, so a scenario can expect it. */
TEST(Gtpc, RejectedCreateSessionResponseReportsItsCause) {
    GtpBytes ies;
    put_ie(ies, IE_CAUSE, 0, bytes("5d00"));    /* 93: APN access denied, no subscription */
    GtpBytes msg = message(GTP_CREATE_SESSION_RESPONSE, true, 0x11111111, 5, ies);
    S8Result r;
    ASSERT_TRUE(gtp_decode_create_session_response(msg.data(), msg.size(), r));
    EXPECT_EQ(93, r.cause);
    EXPECT_TRUE(r.ue_ip.empty());
}

/* The following two tests use messages captured on a live S8 interface
 * (Open5GS SGW-C of a visited network and the home PGW-C, 2026-10-07).
 * They are the only check that does not rest on this file's own reading of
 * TS 29.274. Subscriber identities are not part of the bytes used. */

/* A real PGW's answer: if any of these fields is taken from the wrong place
 * the UE gets no address, or its packets go to a TEID nobody listens on. */
TEST(Gtpc, DecodesCreateSessionResponseOfARealPgw) {
    GtpBytes msg = bytes(
        "4821007300000539000001000200020010005700090187" "00000d64" "0a00010a"
        "4f000500010a2d0007" "7f00010000"
        "4e0022008080211002000010810608080808830608080404000d0408080808000d0408080404"
        "5d002000" "4900010005" "5700090285" "0000f75f" "0a000102" "0200020010" "00"
        "5e0004000000000d");
    S8Result r;
    ASSERT_TRUE(gtp_decode_create_session_response(msg.data(), msg.size(), r));
    EXPECT_EQ(GTP_CAUSE_ACCEPTED, r.cause);
    EXPECT_EQ("10.45.0.7", r.ue_ip);
    EXPECT_EQ("10.0.1.10", r.pgw_c_ip);
    EXPECT_EQ(0x0d64u, r.pgw_c_teid);
    EXPECT_EQ("10.0.1.2", r.pgw_u_ip);
    EXPECT_EQ(0xf75fu, r.pgw_u_teid);
    EXPECT_TRUE(r.pcscf.empty());       /* an internet APN: DNS only in the PCO */
}

/* For the same parameters, the IEs a PGW routes and charges by must be
 * byte-identical to what the real SGW sent. */
TEST(Gtpc, CreateSessionRequestMatchesARealSgwWhereItMust) {
    S8Config c = test_config();
    c.plmn = "26222";
    c.apn = "internet";
    c.tac = 1;
    c.eci = 0x5ee0000;
    c.ambr_ul = c.ambr_dl = 999;
    c.arp = 15;
    c.qci = 9;
    GtpBytes msg = gtp_encode_create_session(c, 1, 0x539, 0x387, 0);
    Header h;
    ASSERT_TRUE(decode_header(msg.data(), msg.size(), h));
    /* the captured request starts 48 20 .. .. 00000000 000001 00 */
    EXPECT_EQ(bytes("4820"), GtpBytes(msg.begin(), msg.begin() + 2));
    EXPECT_EQ(bytes("0000000000000100"), GtpBytes(msg.begin() + 4, msg.begin() + 12));

    std::map<int, GtpBytes> top, bearer;
    ASSERT_TRUE(for_each_ie(h.ies, h.ies_len, [&](uint8_t t, uint8_t inst, const uint8_t *v, size_t n) {
        top[t * 16 + inst] = GtpBytes(v, v + n);
    }));
    EXPECT_EQ(bytes("1862f222000162f22205ee0000"), top[IE_ULI * 16]);
    EXPECT_EQ(bytes("62f222"), top[IE_SERVING_NETWORK * 16]);
    EXPECT_EQ(bytes("06"), top[IE_RAT_TYPE * 16]);
    EXPECT_EQ(bytes("86000005390a0d0d02"), top[IE_FTEID * 16]);
    EXPECT_EQ(bytes("08696e7465726e6574"), top[IE_APN * 16]);
    EXPECT_EQ(bytes("00"), top[IE_SELECTION_MODE * 16]);
    EXPECT_EQ(bytes("01"), top[IE_PDN_TYPE * 16]);
    EXPECT_EQ(bytes("0100000000"), top[IE_PAA * 16]);
    EXPECT_EQ(bytes("00"), top[IE_APN_RESTRICTION * 16]);
    EXPECT_EQ(bytes("000003e7000003e7"), top[IE_AMBR * 16]);

    const GtpBytes &bc = top[IE_BEARER_CONTEXT * 16];
    ASSERT_TRUE(for_each_ie(bc.data(), bc.size(), [&](uint8_t t, uint8_t inst, const uint8_t *v, size_t n) {
        bearer[t * 16 + inst] = GtpBytes(v, v + n);
    }));
    EXPECT_EQ(bytes("05"), bearer[IE_EBI * 16]);
    EXPECT_EQ(bytes("84000003870a0d0d02"), bearer[IE_FTEID * 16 + 2]);
    /* the real SGW set the pre-emption vulnerability bit as well (0x7d);
     * priority level and QCI are what the PGW's policy looks at */
    ASSERT_EQ(22u, bearer[IE_BEARER_QOS * 16].size());
    EXPECT_EQ(0x7d & ~0x01, bearer[IE_BEARER_QOS * 16][0]);
    EXPECT_EQ(9, bearer[IE_BEARER_QOS * 16][1]);
}

/* IEs of a Create Bearer Request a live PGW (Open5GS) sent on S8, from a
 * capture of 2026-10-07: linked EBI 5, one bearer context with a TFT of four
 * filters (TCP 443 and 80 of one host, one downlink and one uplink filter
 * each), the PGW's user plane F-TEID and QCI 9. */
static const char *captured_create_bearer =
    "4900010005"
    "5d00890049000100005400590024"
    "1000133006102ee1c596ffffffff5001bb410001ffff"
    "2101133006112ee1c596ffffffff4001bb510001ffff"
    "1202133006102ee1c596ffffffff500050410001ffff"
    "2303133006112ee1c596ffffffff400050510001ffff"
    "5700090185000030050a000102"
    "500016007d0900000186a000000186a000000000000000000000";

/* What SIPp answers and where it sends uplink depends on these fields: a
 * wrong PGW F-TEID sends the media to a tunnel that does not exist. */
TEST(Gtpc, DecodesCreateBearerRequestOfARealPgw) {
    GtpBytes ies = bytes(captured_create_bearer);
    int lbi = 0;
    std::vector<GtpBearerRequest> b;
    ASSERT_TRUE(gtp_decode_bearer_request(ies.data(), ies.size(), lbi, b));
    EXPECT_EQ(5, lbi);
    ASSERT_EQ(1u, b.size());
    EXPECT_EQ(0, b[0].ebi);             /* the EBI is ours to assign */
    EXPECT_EQ(9, b[0].qci);
    EXPECT_EQ("10.0.1.2", b[0].pgw_u_ip);
    EXPECT_EQ(0x3005u, b[0].pgw_u_teid);
    ASSERT_TRUE(b[0].has_tft);
    ASSERT_TRUE(b[0].tft_ok);
    EXPECT_EQ(TFT_CREATE, b[0].tft_opcode);
    ASSERT_EQ(4u, b[0].tft.size());

    const GtpTftFilter &down = b[0].tft[0], &up = b[0].tft[1];
    uint32_t host;
    inet_pton(AF_INET, "46.225.197.150", &host);
    EXPECT_EQ(1, down.direction);
    EXPECT_EQ(0, down.id);
    EXPECT_EQ(6, down.match.protocol);
    EXPECT_EQ(host, down.match.remote_addr);
    EXPECT_EQ(443, down.match.remote_port_lo);
    EXPECT_EQ(443, down.match.remote_port_hi);
    EXPECT_EQ(1, down.match.local_port_lo);
    EXPECT_EQ(65535, down.match.local_port_hi);

    EXPECT_EQ(2, up.direction);
    EXPECT_EQ(1, up.id);
    EXPECT_EQ(1, up.match.precedence);
    EXPECT_EQ(host, up.match.local_addr);
    EXPECT_EQ(0xffffffffu, up.match.local_mask);
    EXPECT_EQ(443, up.match.local_port_lo);
    EXPECT_FALSE(up.match.never);

    /* Only the uplink filters steer what the UE sends */
    EXPECT_EQ(2u, gtp_uplink_filters(b[0].tft).size());
}

/* An Update Bearer Request changes single filters. If "replace" or "delete"
 * left the old filter in place, media of a re-negotiated call would keep
 * following the old port. */
TEST(Gtpc, TftOperationsChangeSingleFilters) {
    std::vector<GtpTftFilter> tft, in;
    int op = 0;

    /* create: filter 1 uplink, UDP to remote port 30000 */
    GtpBytes create = bytes("21" "21" "05" "05" "3011" "507530");
    ASSERT_TRUE(gtp_decode_tft(create.data(), create.size(), op, in));
    gtp_apply_tft(tft, op, in);
    ASSERT_EQ(1u, tft.size());
    EXPECT_EQ(30000, tft[0].match.remote_port_lo);

    /* replace filter 1: remote port 30002 */
    GtpBytes replace = bytes("81" "21" "05" "05" "3011" "507532");
    ASSERT_TRUE(gtp_decode_tft(replace.data(), replace.size(), op, in));
    EXPECT_EQ(TFT_REPLACE_FILTERS, op);
    gtp_apply_tft(tft, op, in);
    ASSERT_EQ(1u, tft.size());
    EXPECT_EQ(30002, tft[0].match.remote_port_lo);

    /* add filter 2 (downlink only): not an uplink filter */
    GtpBytes add = bytes("61" "12" "06" "03" "507533");
    ASSERT_TRUE(gtp_decode_tft(add.data(), add.size(), op, in));
    gtp_apply_tft(tft, op, in);
    EXPECT_EQ(2u, tft.size());
    EXPECT_EQ(1u, gtp_uplink_filters(tft).size());

    /* delete filter 1 by its identifier */
    GtpBytes del = bytes("a1" "01");
    ASSERT_TRUE(gtp_decode_tft(del.data(), del.size(), op, in));
    gtp_apply_tft(tft, op, in);
    ASSERT_EQ(1u, tft.size());
    EXPECT_EQ(2, tft[0].id);
    EXPECT_TRUE(gtp_uplink_filters(tft).empty());
}

/* A filter with a component this user plane cannot check (here an IPsec
 * SPI) must select nothing rather than everything, and a TFT cut
 * short must be refused, not half applied. */
TEST(Gtpc, TftWithUnsupportedOrTruncatedFilters) {
    std::vector<GtpTftFilter> in;
    int op = 0;
    GtpBytes v6 = bytes("21" "31" "00" "05" "60" "12345678");
    ASSERT_TRUE(gtp_decode_tft(v6.data(), v6.size(), op, in));
    ASSERT_EQ(1u, in.size());
    EXPECT_TRUE(in[0].match.never);

    GtpBytes cut = bytes("21" "21" "05" "09" "3011");
    EXPECT_FALSE(gtp_decode_tft(cut.data(), cut.size(), op, in));
}

/* A PGW allocates by the PDN type and the shape of the PAA: for IPv4v6 it
 * expects type 3 with room for a prefix and an address, and it only names
 * an IPv6 P-CSCF when the PCO asks for one. */
TEST(Gtpc, CreateSessionRequestForIpv6AndDualStack) {
    S8Config cfg = test_config();
    for (int pdn = 2; pdn <= 3; pdn++) {
        cfg.pdn_type = pdn;
        GtpBytes m = gtp_encode_create_session(cfg, 1, 2, 3, 4);
        Header h;
        ASSERT_TRUE(decode_header(m.data(), m.size(), h));
        std::map<int, GtpBytes> top;
        std::map<int, GtpBytes> *t = &top;
        ASSERT_TRUE(for_each_ie(h.ies, h.ies_len, [t](uint8_t type, uint8_t inst, const uint8_t *v, size_t vlen) {
            (*t)[type * 16 + inst] = GtpBytes(v, v + vlen);
        }));
        EXPECT_EQ(GtpBytes(1, pdn), top[IE_PDN_TYPE * 16]);
        ASSERT_EQ(pdn == 2 ? 18u : 22u, top[IE_PAA * 16].size());
        EXPECT_EQ(pdn, top[IE_PAA * 16][0]);
        const GtpBytes &pco = top[IE_PCO * 16];
        /* IPv6-only: P-CSCF v6, DNS v6, IM CN flag; dual stack: all five */
        EXPECT_EQ(pdn == 2 ? bytes("80" "000100" "000300" "000200")
                           : bytes("80" "000100" "000300" "000c00" "000d00" "000200"), pco);
    }
}

/* Both addresses of a dual-stack answer are needed: SIP runs from one, the
 * user plane has to know both. The IPv4 address sits behind the 17 octets
 * of prefix length and prefix; read from the wrong offset it is garbage. */
TEST(Gtpc, CreateSessionResponseWithIpv6Addresses) {
    GtpBytes ies, bc;
    put_ie(ies, IE_CAUSE, 0, bytes("1000"));
    put_ie(ies, IE_FTEID, 1, bytes("87" "00001001" "0a00010a"));
    put_ie(ies, IE_PAA, 0, bytes("03" "40" "cafe0000004600070000000000000001" "0a2e0007"));
    put_ie(ies, IE_PCO, 0, bytes("80" "000110" "2001067c000000000000000000000153" "000c04" "2ee1c599"));
    put_ie8(bc, IE_EBI, 0, 5);
    put_ie(bc, IE_FTEID, 2, bytes("85" "00002002" "0a000102"));
    put_ie(ies, IE_BEARER_CONTEXT, 0, bc);
    GtpBytes m = message(GTP_CREATE_SESSION_RESPONSE, true, 7, 1, ies);
    S8Result r;
    ASSERT_TRUE(gtp_decode_create_session_response(m.data(), m.size(), r));
    EXPECT_EQ(3, r.pdn_type);
    EXPECT_EQ("10.46.0.7", r.ue_ip);
    EXPECT_EQ("cafe:0:46:7::1", r.ue_ip6);
    EXPECT_EQ("46.225.197.153", r.pcscf);
    EXPECT_EQ("2001:67c::153", r.pcscf6);

    /* IPv6 only: no IPv4 address may be invented */
    ies.clear();
    put_ie(ies, IE_CAUSE, 0, bytes("1000"));
    put_ie(ies, IE_PAA, 0, bytes("02" "40" "cafe0000004600070000000000000001"));
    m = message(GTP_CREATE_SESSION_RESPONSE, true, 7, 1, ies);
    ASSERT_TRUE(gtp_decode_create_session_response(m.data(), m.size(), r));
    EXPECT_EQ(2, r.pdn_type);
    EXPECT_TRUE(r.ue_ip.empty());
    EXPECT_EQ("cafe:0:46:7::1", r.ue_ip6);
}

/* The voice bearer of an IPv6 call comes with IPv6 filter components
 * (address with prefix length). They have to be understood, or the media
 * of every IPv6 call stays on the default bearer. */
TEST(Gtpc, TftWithIpv6Components) {
    std::vector<GtpTftFilter> in;
    int op = 0;
    /* uplink: UDP, remote 2001:db8::9/128 port 30000, local cafe:0:46:7::/64 */
    GtpBytes tft = bytes("21" "21" "00" "29"
                         "3011"
                         "21" "20010db8000000000000000000000009" "80"
                         "507530"
                         "23" "cafe0000004600070000000000000000" "40");
    ASSERT_TRUE(gtp_decode_tft(tft.data(), tft.size(), op, in));
    ASSERT_EQ(1u, in.size());
    const GtpuFilter &f = in[0].match;
    EXPECT_FALSE(f.never);
    EXPECT_EQ(128, f.remote6_len);
    EXPECT_EQ(64, f.local6_len);
    EXPECT_EQ(0x20, f.remote6[0]);
    EXPECT_EQ(0x09, f.remote6[15]);
    EXPECT_EQ(30000, f.remote_port_lo);
    EXPECT_EQ(17, f.protocol);
}

TEST(Gtpc, TruncatedMessagesAreRefused) {
    GtpBytes msg = gtp_encode_create_session(test_config(), 1, 1, 1, 0);
    S8Result r;
    Header h;
    msg.resize(msg.size() - 3);
    EXPECT_FALSE(decode_header(msg.data(), msg.size(), h));
    EXPECT_FALSE(gtp_decode_create_session_response(msg.data(), msg.size(), r));
}
#endif /* GTEST */

#endif /* USE_S8 */
