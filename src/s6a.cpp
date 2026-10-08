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
 *  S6a client (3GPP TS 29.272) on the Diameter base protocol (RFC 6733):
 *  SIPp as the visited MME toward the home HSS.
 *
 *  One connection for the process, over SCTP or TCP, to the peer given with
 *  -s6a_peer (the home network's DRA, or the HSS itself). It is opened with
 *  the first request: capabilities exchange, then the main loop drives it.
 *  There is no failover and no second peer; a lost connection fails the
 *  requests in flight and is opened again with the next one.
 *
 *  IPv4 only.
 */

#ifdef USE_S8

#include "s6a.hpp"
#include "gtpc.hpp"
#include "sipp.hpp"

#include <cstdarg>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <map>
#include <set>

#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/sctp.h>

/* Command codes: RFC 6733 §3.1, TS 29.272 §7.2.2 */
enum {
    CMD_CER = 257,              /* Capabilities-Exchange */
    CMD_DWR = 280,              /* Device-Watchdog */
    CMD_DPR = 282,              /* Disconnect-Peer */
    CMD_ULR = 316,              /* Update-Location, TS 29.272 §7.2.3 */
    CMD_CLR = 317,              /* Cancel-Location, §7.2.7 */
    CMD_AIR = 318,              /* Authentication-Information, §7.2.5 */
    CMD_IDR = 319,              /* Insert-Subscriber-Data, §7.2.9 */
    CMD_DSR = 320,              /* Delete-Subscriber-Data, §7.2.11 */
    CMD_PUR = 321,              /* Purge-UE, §7.2.13 */
    CMD_RSR = 322,              /* Reset, §7.2.15 */
    APP_S6A = 16777251,         /* TS 29.272 §7.1.8 */
    VENDOR_3GPP = 10415,
    DIAMETER_PORT = 3868,
    SCTP_PPID_DIAMETER = 46     /* RFC 6733 §2.1.1 */
};

/* Message flags (RFC 6733 §3) and AVP flags (§4.1) */
enum {
    FLAG_REQUEST = 0x80, FLAG_PROXIABLE = 0x40, FLAG_ERROR = 0x20,
    AVP_VENDOR = 0x80, AVP_MANDATORY = 0x40
};

/* Base protocol AVPs, RFC 6733 §4.5 and the clause given */
enum {
    AVP_USER_NAME = 1,                      /* §8.14: the IMSI on S6a */
    AVP_HOST_IP_ADDRESS = 257,              /* §5.3.5 */
    AVP_AUTH_APPLICATION_ID = 258,          /* §6.8 */
    AVP_VENDOR_SPECIFIC_APPLICATION_ID = 260,   /* §6.11 */
    AVP_SESSION_ID = 263,                   /* §8.8 */
    AVP_ORIGIN_HOST = 264,                  /* §6.3 */
    AVP_SUPPORTED_VENDOR_ID = 265,          /* §5.3.6 */
    AVP_VENDOR_ID = 266,                    /* §5.3.3 */
    AVP_FIRMWARE_REVISION = 267,            /* §5.3.4 */
    AVP_RESULT_CODE = 268,                  /* §7.1 */
    AVP_PRODUCT_NAME = 269,                 /* §5.3.7 */
    AVP_DISCONNECT_CAUSE = 273,             /* §5.4.3 */
    AVP_AUTH_SESSION_STATE = 277,           /* §8.11 */
    AVP_ORIGIN_STATE_ID = 278,              /* §8.16 */
    AVP_DESTINATION_REALM = 283,            /* §6.6 */
    AVP_ORIGIN_REALM = 296,                 /* §6.4 */
    AVP_EXPERIMENTAL_RESULT = 297,          /* §7.6 */
    AVP_EXPERIMENTAL_RESULT_CODE = 298,     /* §7.7 */
    AVP_SERVICE_SELECTION = 493             /* RFC 5778 §6.2: the APN */
};

/* 3GPP AVPs (vendor 10415): TS 29.272 Table 7.3.1/1 with the clause, and
 * those it takes from TS 29.212, TS 29.214 and TS 29.329 */
enum {
    AVP_MAX_REQUESTED_BANDWIDTH_DL = 515,   /* TS 29.214 §5.3.14, bit/s */
    AVP_MAX_REQUESTED_BANDWIDTH_UL = 516,   /* TS 29.214 §5.3.15, bit/s */
    AVP_MSISDN = 701,                       /* TS 29.329 §6.3.2, TBCD */
    AVP_QOS_CLASS_IDENTIFIER = 1028,        /* TS 29.212 §5.3.17 */
    AVP_RAT_TYPE = 1032,                    /* TS 29.212 §5.3.31 */
    AVP_ALLOCATION_RETENTION_PRIORITY = 1034,   /* TS 29.212 §5.3.32 */
    AVP_PRIORITY_LEVEL = 1046,              /* TS 29.212 §5.3.45 */
    AVP_SUBSCRIPTION_DATA = 1400,           /* §7.3.2 */
    AVP_TERMINAL_INFORMATION = 1401,        /* §7.3.3 */
    AVP_IMEI = 1402,                        /* §7.3.4 */
    AVP_SOFTWARE_VERSION = 1403,            /* §7.3.5 */
    AVP_ULR_FLAGS = 1405,                   /* §7.3.7 */
    AVP_VISITED_PLMN_ID = 1407,             /* §7.3.9 */
    AVP_REQUESTED_EUTRAN_AUTH_INFO = 1408,  /* §7.3.11 */
    AVP_NUMBER_OF_REQUESTED_VECTORS = 1410, /* §7.3.14 */
    AVP_IMMEDIATE_RESPONSE_PREFERRED = 1412,    /* §7.3.16 */
    AVP_CANCELLATION_TYPE = 1420,           /* §7.3.24 */
    AVP_APN_CONFIGURATION_PROFILE = 1429,   /* §7.3.34 */
    AVP_APN_CONFIGURATION = 1430,           /* §7.3.35 */
    AVP_EPS_SUBSCRIBED_QOS_PROFILE = 1431,  /* §7.3.37 */
    AVP_AMBR = 1435,                        /* §7.3.41 */
    AVP_PDN_TYPE = 1456                     /* §7.3.62 */
};

enum {
    RAT_TYPE_EUTRAN = 1004,                 /* TS 29.212 §5.3.31 */
    /* ULR-Flags (§7.3.7): bit 1 S6a/S6d-Indicator (this is S6a), bit 5
     * Initial-Attach-Indicator (the HSS cancels the previous MME) */
    ULR_FLAGS = 0x02 | 0x20,
    AUTH_SESSION_STATE_NONE = 1             /* NO_STATE_MAINTAINED, TS 29.272 §7.1.4 */
};

enum { KIND_AIR = 1, KIND_ULR, KIND_PUR };

/* --- codec -------------------------------------------------------------- */

static void put32(DiaBytes &b, uint32_t v)
{
    b.push_back(v >> 24); b.push_back(v >> 16); b.push_back(v >> 8); b.push_back(v);
}
static uint32_t get24(const uint8_t *p) { return ((uint32_t)p[0] << 16) | (p[1] << 8) | p[2]; }
static uint32_t get32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | get24(p + 1); }

DiaBytes dia_avp(uint32_t code, uint32_t vendor, const DiaBytes &data, bool mandatory)
{
    /* Code, flags, 24-bit length of header and data without padding, the
     * Vendor-Id if the V bit is set, data, padding to 4 octets (§4.1) */
    DiaBytes a;
    size_t len = (vendor ? 12 : 8) + data.size();
    put32(a, code);
    a.push_back((vendor ? AVP_VENDOR : 0) | (mandatory ? AVP_MANDATORY : 0));
    a.push_back(len >> 16); a.push_back(len >> 8); a.push_back(len);
    if (vendor) {
        put32(a, vendor);
    }
    a.insert(a.end(), data.begin(), data.end());
    a.resize((a.size() + 3) & ~(size_t)3, 0);
    return a;
}

DiaBytes dia_avp_u32(uint32_t code, uint32_t vendor, uint32_t value, bool mandatory)
{
    DiaBytes d;
    put32(d, value);
    return dia_avp(code, vendor, d, mandatory);
}

DiaBytes dia_avp_str(uint32_t code, uint32_t vendor, const std::string &value, bool mandatory)
{
    return dia_avp(code, vendor, DiaBytes(value.begin(), value.end()), mandatory);
}

DiaBytes dia_message(uint32_t cmd, uint32_t app, uint8_t flags, uint32_t hop_by_hop,
                     uint32_t end_to_end, const DiaBytes &avps)
{
    /* Version 1, 24-bit message length, flags, 24-bit command code,
     * Application-Id, Hop-by-Hop and End-to-End Identifier (§3) */
    DiaBytes m;
    size_t len = 20 + avps.size();
    m.push_back(1);
    m.push_back(len >> 16); m.push_back(len >> 8); m.push_back(len);
    m.push_back(flags);
    m.push_back(cmd >> 16); m.push_back(cmd >> 8); m.push_back(cmd);
    put32(m, app);
    put32(m, hop_by_hop);
    put32(m, end_to_end);
    m.insert(m.end(), avps.begin(), avps.end());
    return m;
}

bool dia_decode_header(const uint8_t *msg, size_t len, DiaHeader &h)
{
    if (len < 20 || msg[0] != 1) {
        return false;
    }
    size_t total = get24(msg + 1);
    if (total < 20 || total > len) {
        return false;
    }
    h.request = (msg[4] & FLAG_REQUEST) != 0;
    h.proxiable = (msg[4] & FLAG_PROXIABLE) != 0;
    h.error = (msg[4] & FLAG_ERROR) != 0;
    h.cmd = get24(msg + 5);
    h.app = get32(msg + 8);
    h.hop_by_hop = get32(msg + 12);
    h.end_to_end = get32(msg + 16);
    h.avps = msg + 20;
    h.avps_len = total - 20;
    return true;
}

/* Call fn(avp) for each AVP; false on a broken AVP header */
template <typename F>
static bool for_each_avp(const uint8_t *p, size_t len, F fn)
{
    size_t off = 0;
    while (off < len) {
        if (off + 8 > len) {
            return false;
        }
        DiaAvp a;
        a.code = get32(p + off);
        a.flags = p[off + 4];
        size_t alen = get24(p + off + 5);
        size_t hdr = (a.flags & AVP_VENDOR) ? 12 : 8;
        if (alen < hdr || off + alen > len) {
            return false;
        }
        a.vendor = (a.flags & AVP_VENDOR) ? get32(p + off + 8) : 0;
        a.data = p + off + hdr;
        a.len = alen - hdr;
        fn(a);
        off += (alen + 3) & ~(size_t)3;
    }
    return true;
}

bool dia_find(const uint8_t *avps, size_t len, uint32_t code, uint32_t vendor, DiaAvp &out)
{
    bool found = false;
    DiaAvp *o = &out;
    bool *f = &found;
    for_each_avp(avps, len, [o, f, code, vendor](const DiaAvp &a) {
        if (!*f && a.code == code && a.vendor == vendor) {
            *o = a;
            *f = true;
        }
    });
    return found;
}

static bool find_u32(const uint8_t *avps, size_t len, uint32_t code, uint32_t vendor, uint32_t &v)
{
    DiaAvp a;
    if (!dia_find(avps, len, code, vendor, a) || a.len < 4) {
        return false;
    }
    v = get32(a.data);
    return true;
}

static void append(DiaBytes &b, const DiaBytes &o) { b.insert(b.end(), o.begin(), o.end()); }

/* "<mcc><mnc>" split into MCC and a 3-digit MNC, as the 3GPP domain names
 * want it (TS 23.003 §19.2) */
static bool plmn_parts(const std::string &mccmnc, std::string &mcc, std::string &mnc)
{
    if (mccmnc.size() != 5 && mccmnc.size() != 6) {
        return false;
    }
    mcc = mccmnc.substr(0, 3);
    mnc = mccmnc.substr(3);
    if (mnc.size() == 2) {
        mnc = "0" + mnc;
    }
    return true;
}

std::string s6a_default_realm(const std::string &mccmnc)
{
    std::string mcc, mnc;
    if (!plmn_parts(mccmnc, mcc, mnc)) {
        return "";
    }
    return "epc.mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org";
}

std::string s6a_default_host(const std::string &mccmnc)
{
    /* MME node FQDN with MME code 01 in MME group 0001 (TS 23.003 §19.4.2.4) */
    std::string realm = s6a_default_realm(mccmnc);
    return realm.empty() ? "" : "mmec01.mmegi0001.mme." + realm;
}

/* The AVPs every S6a request starts with (TS 29.272 §7.2.x ABNF) */
static DiaBytes request_head(const S6aIdentity &id, const std::string &session_id,
                             const std::string &imsi)
{
    DiaBytes a, vsa;
    append(a, dia_avp_str(AVP_SESSION_ID, 0, session_id));
    append(a, dia_avp_u32(AVP_AUTH_SESSION_STATE, 0, AUTH_SESSION_STATE_NONE));
    append(a, dia_avp_str(AVP_ORIGIN_HOST, 0, id.origin_host));
    append(a, dia_avp_str(AVP_ORIGIN_REALM, 0, id.origin_realm));
    append(a, dia_avp_str(AVP_DESTINATION_REALM, 0, id.dest_realm));
    append(a, dia_avp_str(AVP_USER_NAME, 0, imsi));
    append(vsa, dia_avp_u32(AVP_VENDOR_ID, 0, VENDOR_3GPP));
    append(vsa, dia_avp_u32(AVP_AUTH_APPLICATION_ID, 0, APP_S6A));
    append(a, dia_avp(AVP_VENDOR_SPECIFIC_APPLICATION_ID, 0, vsa));
    return a;
}

static DiaBytes visited_plmn_avp(const std::string &mccmnc)
{
    /* Three octets, coded like the PLMN identity of TS 24.008 (§7.3.9) */
    uint8_t plmn[3] = { 0, 0, 0 };
    gtp_plmn(mccmnc, plmn);
    return dia_avp(AVP_VISITED_PLMN_ID, VENDOR_3GPP, DiaBytes(plmn, plmn + 3));
}

DiaBytes s6a_encode_air(const S6aIdentity &id, const std::string &session_id,
                        const std::string &imsi, uint32_t hop_by_hop, uint32_t end_to_end)
{
    /* Authentication-Information-Request, TS 29.272 §7.2.5: one E-UTRAN
     * vector for the visited PLMN, which the HSS binds KASME to */
    DiaBytes a = request_head(id, session_id, imsi), req;
    append(req, dia_avp_u32(AVP_NUMBER_OF_REQUESTED_VECTORS, VENDOR_3GPP, 1));
    append(req, dia_avp_u32(AVP_IMMEDIATE_RESPONSE_PREFERRED, VENDOR_3GPP, 1));
    append(a, dia_avp(AVP_REQUESTED_EUTRAN_AUTH_INFO, VENDOR_3GPP, req));
    append(a, visited_plmn_avp(id.visited_plmn));
    return dia_message(CMD_AIR, APP_S6A, FLAG_REQUEST | FLAG_PROXIABLE, hop_by_hop, end_to_end, a);
}

DiaBytes s6a_encode_ulr(const S6aIdentity &id, const std::string &session_id,
                        const std::string &imsi, const std::string &imei,
                        uint32_t hop_by_hop, uint32_t end_to_end)
{
    /* Update-Location-Request, TS 29.272 §7.2.3 */
    DiaBytes a = request_head(id, session_id, imsi);
    if (!imei.empty()) {
        /* IMEI is 14 digits; a 16-digit IMEISV carries the software
         * version in its last two (§7.3.4, §7.3.5) */
        DiaBytes ti;
        append(ti, dia_avp_str(AVP_IMEI, VENDOR_3GPP, imei.substr(0, 14)));
        if (imei.size() >= 16) {
            append(ti, dia_avp_str(AVP_SOFTWARE_VERSION, VENDOR_3GPP, imei.substr(14, 2)));
        }
        append(a, dia_avp(AVP_TERMINAL_INFORMATION, VENDOR_3GPP, ti));
    }
    append(a, dia_avp_u32(AVP_RAT_TYPE, VENDOR_3GPP, RAT_TYPE_EUTRAN));
    append(a, dia_avp_u32(AVP_ULR_FLAGS, VENDOR_3GPP, ULR_FLAGS));
    append(a, visited_plmn_avp(id.visited_plmn));
    return dia_message(CMD_ULR, APP_S6A, FLAG_REQUEST | FLAG_PROXIABLE, hop_by_hop, end_to_end, a);
}

DiaBytes s6a_encode_pur(const S6aIdentity &id, const std::string &session_id,
                        const std::string &imsi, uint32_t hop_by_hop, uint32_t end_to_end)
{
    /* Purge-UE-Request, TS 29.272 §7.2.13 */
    DiaBytes a = request_head(id, session_id, imsi);
    return dia_message(CMD_PUR, APP_S6A, FLAG_REQUEST | FLAG_PROXIABLE, hop_by_hop, end_to_end, a);
}

int s6a_result_code(const uint8_t *msg, size_t len)
{
    DiaHeader h;
    DiaAvp exp;
    uint32_t code = 0;
    if (!dia_decode_header(msg, len, h)) {
        return 0;
    }
    if (find_u32(h.avps, h.avps_len, AVP_RESULT_CODE, 0, code)) {
        return code;
    }
    /* S6a's own errors come as Experimental-Result (TS 29.272 §7.4) */
    if (dia_find(h.avps, h.avps_len, AVP_EXPERIMENTAL_RESULT, 0, exp) &&
        find_u32(exp.data, exp.len, AVP_EXPERIMENTAL_RESULT_CODE, 0, code)) {
        return code;
    }
    return 0;
}

/* AMBR (§7.3.41) in bit/s to the kbit/s of GTPv2's APN-AMBR */
static void ambr(const DiaAvp &a, uint32_t &ul, uint32_t &dl)
{
    uint32_t v;
    if (find_u32(a.data, a.len, AVP_MAX_REQUESTED_BANDWIDTH_UL, VENDOR_3GPP, v)) {
        ul = v / 1000;
    }
    if (find_u32(a.data, a.len, AVP_MAX_REQUESTED_BANDWIDTH_DL, VENDOR_3GPP, v)) {
        dl = v / 1000;
    }
}

static std::string tbcd_digits(const uint8_t *p, size_t len)
{
    std::string out;
    for (size_t i = 0; i < len; i++) {
        int lo = p[i] & 0x0f, hi = p[i] >> 4;
        if (lo <= 9) {
            out += (char)('0' + lo);
        }
        if (hi <= 9) {
            out += (char)('0' + hi);
        }
    }
    return out;
}

bool s6a_decode_subscription(const uint8_t *msg, size_t len, const std::string &apn,
                             S6aSubscription &out)
{
    DiaHeader h;
    DiaAvp sub, a;
    out = S6aSubscription();
    if (!dia_decode_header(msg, len, h) ||
        !dia_find(h.avps, h.avps_len, AVP_SUBSCRIPTION_DATA, VENDOR_3GPP, sub)) {
        return false;
    }
    if (dia_find(sub.data, sub.len, AVP_MSISDN, VENDOR_3GPP, a)) {
        out.msisdn = tbcd_digits(a.data, a.len);
    }
    if (dia_find(sub.data, sub.len, AVP_AMBR, VENDOR_3GPP, a)) {
        ambr(a, out.ue_ambr_ul, out.ue_ambr_dl);        /* UE-AMBR */
    }
    if (!dia_find(sub.data, sub.len, AVP_APN_CONFIGURATION_PROFILE, VENDOR_3GPP, a)) {
        return true;
    }
    /* One APN-Configuration per subscribed APN (§7.3.35); take the one
     * whose Service-Selection is the APN asked for */
    S6aSubscription *o = &out;
    const std::string *want = &apn;
    for_each_avp(a.data, a.len, [o, want](const DiaAvp &cfg) {
        if (cfg.code != AVP_APN_CONFIGURATION || cfg.vendor != VENDOR_3GPP) {
            return;
        }
        o->apn_count++;
        DiaAvp f, arp;
        uint32_t v;
        if (o->apn_found || !dia_find(cfg.data, cfg.len, AVP_SERVICE_SELECTION, 0, f) ||
            std::string((const char *)f.data, f.len) != *want) {
            return;
        }
        o->apn_found = true;
        o->apn = *want;
        if (find_u32(cfg.data, cfg.len, AVP_PDN_TYPE, VENDOR_3GPP, v)) {
            o->pdn_type = v;
        }
        if (dia_find(cfg.data, cfg.len, AVP_EPS_SUBSCRIBED_QOS_PROFILE, VENDOR_3GPP, f)) {
            if (find_u32(f.data, f.len, AVP_QOS_CLASS_IDENTIFIER, VENDOR_3GPP, v)) {
                o->qci = v;
            }
            if (dia_find(f.data, f.len, AVP_ALLOCATION_RETENTION_PRIORITY, VENDOR_3GPP, arp) &&
                find_u32(arp.data, arp.len, AVP_PRIORITY_LEVEL, VENDOR_3GPP, v)) {
                o->arp = v;
            }
        }
        if (dia_find(cfg.data, cfg.len, AVP_AMBR, VENDOR_3GPP, f)) {
            ambr(f, o->apn_ambr_ul, o->apn_ambr_dl);    /* APN-AMBR */
        }
    });
    return true;
}

/* --- endpoint ----------------------------------------------------------- */

/* The Diameter node of this process (the "MME"): one connection, the
 * identifier spaces, and the maps that route what arrives to a session. */
class S6aEndpoint {
public:
    static bool open(std::string &error);
    static void drop(const char *why);
    static bool send(const DiaBytes &msg);
    static void receive();
    static void handle(const uint8_t *msg, size_t len);
    static void answer(const DiaHeader &req, int result, const DiaBytes &extra);
    static bool next_message(DiaBytes &msg);
    static std::string new_session_id(const std::string &imsi);

    static int fd;
    static bool sctp;
    static S6aIdentity id;
    static DiaBytes rx;
    static uint32_t next_hbh, next_e2e, session_seq, start_time;
    static unsigned long retry_at, last_rx, watchdog_sent;
    static std::set<S6aSession *> all;
    static std::map<uint32_t, S6aSession *> by_hbh;         /* our pending requests */
    static std::map<std::string, S6aSession *> by_imsi;
};

int S6aEndpoint::fd = -1;
bool S6aEndpoint::sctp = false;
S6aIdentity S6aEndpoint::id;
DiaBytes S6aEndpoint::rx;
uint32_t S6aEndpoint::next_hbh = 0;
uint32_t S6aEndpoint::next_e2e = 0;
uint32_t S6aEndpoint::session_seq = 0;
uint32_t S6aEndpoint::start_time = 0;
unsigned long S6aEndpoint::retry_at = 0;
unsigned long S6aEndpoint::last_rx = 0;
unsigned long S6aEndpoint::watchdog_sent = 0;
std::set<S6aSession *> S6aEndpoint::all;
std::map<uint32_t, S6aSession *> S6aEndpoint::by_hbh;
std::map<std::string, S6aSession *> S6aEndpoint::by_imsi;

/* Tw of RFC 3539 §3.4.1: a watchdog request after this much silence, and
 * the connection counts as dead when that goes unanswered as long */
#define S6A_WATCHDOG_MS 30000
/* Capabilities exchange and connect are done synchronously */
#define S6A_CONNECT_TIMEOUT_MS 3000

std::string S6aEndpoint::new_session_id(const std::string &imsi)
{
    /* <DiameterIdentity>;<high 32 bits>;<low 32 bits>;<optional> (§8.8) */
    char buf[64];
    snprintf(buf, sizeof(buf), ";%u;%u;", start_time, ++session_seq);
    return id.origin_host + buf + imsi;
}

bool S6aEndpoint::next_message(DiaBytes &msg)
{
    if (rx.size() < 20) {
        return false;
    }
    size_t total = get24(rx.data() + 1);
    if (rx[0] != 1 || total < 20) {
        drop("the peer sent something that is not Diameter");
        return false;
    }
    if (rx.size() < total) {
        return false;
    }
    msg.assign(rx.begin(), rx.begin() + total);
    rx.erase(rx.begin(), rx.begin() + total);
    return true;
}

bool S6aEndpoint::send(const DiaBytes &msg)
{
    /* One send per message: on SCTP that makes it one user message, as
     * RFC 6733 §2.1.1 wants */
    if (fd < 0 || ::send(fd, msg.data(), msg.size(), MSG_NOSIGNAL) != (ssize_t)msg.size()) {
        if (fd >= 0) {
            drop(strerror(errno));
        }
        return false;
    }
    return true;
}

bool S6aEndpoint::open(std::string &error)
{
    if (fd >= 0) {
        return true;
    }
    if (retry_at && clock_tick < retry_at) {
        error = "no connection to the Diameter peer (retrying shortly)";
        return false;
    }
    retry_at = clock_tick + 5000;
    if (!s6a_peer) {
        error = "no Diameter peer given (-s6a_peer)";
        return false;
    }
    sctp = strcmp(s6a_transport, "tcp") != 0;
    if (sctp && strcmp(s6a_transport, "sctp") != 0) {
        error = std::string("-s6a_transport is 'sctp' or 'tcp', not '") + s6a_transport + "'";
        return false;
    }
    std::string plmn = visited_plmn ? visited_plmn : "";
    id.visited_plmn = plmn;
    id.origin_host = s6a_origin_host ? s6a_origin_host : s6a_default_host(plmn);
    id.origin_realm = s6a_origin_realm ? s6a_origin_realm : s6a_default_realm(plmn);
    id.dest_realm = s6a_dest_realm ? s6a_dest_realm : "";
    if (id.origin_host.empty() || id.origin_realm.empty() || id.dest_realm.empty()) {
        error = "S6a needs -s6a_dest_realm, and -visited_plmn or -s6a_origin_host and -s6a_origin_realm";
        return false;
    }

    /* host[:port] */
    std::string host(s6a_peer), port("3868");
    size_t colon = host.rfind(':');
    if (colon != std::string::npos) {
        port = host.substr(colon + 1);
        host.resize(colon);
    }
    struct addrinfo hints, *res = nullptr;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) {
        error = "cannot resolve the Diameter peer '" + host + "' (IPv4 only)";
        return false;
    }
    int s = socket(AF_INET, SOCK_STREAM, sctp ? IPPROTO_SCTP : IPPROTO_TCP);
    struct timeval tv = { S6A_CONNECT_TIMEOUT_MS / 1000, 0 };
    int one = 1;
    if (s >= 0) {
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (sctp) {
            /* Payload protocol identifier 46 on every message, and no
             * Nagle (RFC 6733 §2.1.1, RFC 3539 §3.2) */
            struct sctp_sndrcvinfo info;
            memset(&info, 0, sizeof(info));
            info.sinfo_ppid = htonl(SCTP_PPID_DIAMETER);
            setsockopt(s, IPPROTO_SCTP, SCTP_DEFAULT_SEND_PARAM, &info, sizeof(info));
            setsockopt(s, IPPROTO_SCTP, SCTP_NODELAY, &one, sizeof(one));
        } else {
            setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        }
    }
    /* One local address: an unbound SCTP socket offers the peer every
     * address of the host (multi-homing, RFC 9260 §6.4), which neither a
     * NAT in between nor a test wants */
    const char *bind_ip = s6a_local_ip ? s6a_local_ip : s8_local_ip;
    bool bound = true;
    if (s >= 0 && bind_ip) {
        struct sockaddr_in local;
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        bound = inet_pton(AF_INET, bind_ip, &local.sin_addr) == 1 &&
                bind(s, (struct sockaddr *)&local, sizeof(local)) == 0;
    }
    if (s < 0 || !bound || connect(s, res->ai_addr, res->ai_addrlen) < 0) {
        error = std::string("cannot connect to the Diameter peer ") + s6a_peer + " over " +
                (sctp ? "SCTP" : "TCP") + ": " + strerror(errno);
        freeaddrinfo(res);
        if (s >= 0) {
            close(s);
        }
        return false;
    }
    freeaddrinfo(res);

    start_time = (uint32_t)time(nullptr);
    /* §3: the high bits of the identifiers start from the clock, so they
     * do not repeat those of a previous run */
    next_hbh = next_e2e = start_time << 20;
    /* Session-Ids must not repeat those of another SIPp started in the
     * same second with the same Origin-Host (§8.8: eternally unique) */
    session_seq = ((uint32_t)getpid() & 0xfff) << 20;

    /* Capabilities-Exchange-Request, RFC 6733 §5.3.1 */
    struct sockaddr_in local;
    socklen_t llen = sizeof(local);
    memset(&local, 0, sizeof(local));
    getsockname(s, (struct sockaddr *)&local, &llen);
    DiaBytes a, addr, vsa;
    addr.push_back(0); addr.push_back(1);       /* address family 1: IPv4 (§4.3.1) */
    addr.insert(addr.end(), (uint8_t *)&local.sin_addr, (uint8_t *)&local.sin_addr + 4);
    append(a, dia_avp_str(AVP_ORIGIN_HOST, 0, id.origin_host));
    append(a, dia_avp_str(AVP_ORIGIN_REALM, 0, id.origin_realm));
    append(a, dia_avp(AVP_HOST_IP_ADDRESS, 0, addr));
    append(a, dia_avp_u32(AVP_VENDOR_ID, 0, 0));
    append(a, dia_avp_str(AVP_PRODUCT_NAME, 0, "SIPp", false));
    append(a, dia_avp_u32(AVP_ORIGIN_STATE_ID, 0, start_time));
    append(a, dia_avp_u32(AVP_SUPPORTED_VENDOR_ID, 0, VENDOR_3GPP));
    append(vsa, dia_avp_u32(AVP_VENDOR_ID, 0, VENDOR_3GPP));
    append(vsa, dia_avp_u32(AVP_AUTH_APPLICATION_ID, 0, APP_S6A));
    append(a, dia_avp(AVP_VENDOR_SPECIFIC_APPLICATION_ID, 0, vsa));
    DiaBytes cer = dia_message(CMD_CER, 0, FLAG_REQUEST, ++next_hbh, ++next_e2e, a);

    fd = s;
    rx.clear();
    int result = -1;
    if (send(cer)) {
        /* Wait for the answer here: nothing else may be sent before it */
        DiaBytes cea;
        struct pollfd p = { fd, POLLIN, 0 };
        uint8_t buf[8192];
        while (fd >= 0 && !next_message(cea) && poll(&p, 1, S6A_CONNECT_TIMEOUT_MS) > 0) {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) {
                break;
            }
            rx.insert(rx.end(), buf, buf + n);
        }
        DiaHeader h;
        if (!cea.empty() && dia_decode_header(cea.data(), cea.size(), h) && h.cmd == CMD_CER) {
            result = s6a_result_code(cea.data(), cea.size());
        }
    }
    if (result != DIA_SUCCESS) {
        char buf[160];
        if (result < 0) {
            snprintf(buf, sizeof(buf), "no Capabilities-Exchange-Answer from %s", s6a_peer);
        } else {
            snprintf(buf, sizeof(buf), "%s refused the capabilities exchange of '%s', Result-Code %d",
                     s6a_peer, id.origin_host.c_str(), result);
        }
        error = buf;
        if (fd >= 0) {
            close(fd);
            fd = -1;
        }
        return false;
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
    last_rx = clock_tick;
    watchdog_sent = 0;
    retry_at = 0;
    LOG_MSG("S6a: connected to %s over %s as %s (realm %s)\n", s6a_peer, sctp ? "SCTP" : "TCP",
            id.origin_host.c_str(), id.origin_realm.c_str());
    return true;
}

void S6aEndpoint::drop(const char *why)
{
    if (fd < 0) {
        return;
    }
    close(fd);
    fd = -1;
    rx.clear();
    retry_at = clock_tick + 5000;
    WARNING("S6a: connection to %s lost: %s", s6a_peer, why);
    std::vector<S6aSession *> waiting;
    for (std::map<uint32_t, S6aSession *>::iterator it = by_hbh.begin(); it != by_hbh.end(); ++it) {
        waiting.push_back(it->second);
    }
    for (size_t i = 0; i < waiting.size(); i++) {
        waiting[i]->fail("connection to the Diameter peer lost");
    }
}

void S6aEndpoint::answer(const DiaHeader &req, int result, const DiaBytes &extra)
{
    /* An answer keeps the identifiers and the P bit of its request (§3, §6.2) */
    DiaBytes a = extra;
    append(a, dia_avp_u32(AVP_RESULT_CODE, 0, result));
    append(a, dia_avp_str(AVP_ORIGIN_HOST, 0, id.origin_host));
    append(a, dia_avp_str(AVP_ORIGIN_REALM, 0, id.origin_realm));
    send(dia_message(req.cmd, req.app,
                     (req.proxiable ? FLAG_PROXIABLE : 0) | (result >= 3000 && result < 4000 ? FLAG_ERROR : 0),
                     req.hop_by_hop, req.end_to_end, a));
}

void S6aEndpoint::handle(const uint8_t *msg, size_t len)
{
    DiaHeader h;
    if (!dia_decode_header(msg, len, h)) {
        return;
    }
    if (!h.request) {
        if (h.cmd == CMD_DWR) {
            watchdog_sent = 0;
            return;
        }
        std::map<uint32_t, S6aSession *>::iterator it = by_hbh.find(h.hop_by_hop);
        if (it != by_hbh.end()) {
            it->second->on_answer(msg, len);
        }
        return;
    }

    if (h.cmd == CMD_DWR) {
        answer(h, DIA_SUCCESS, dia_avp_u32(AVP_ORIGIN_STATE_ID, 0, start_time));
        return;
    }
    if (h.cmd == CMD_DPR) {
        answer(h, DIA_SUCCESS, DiaBytes());
        drop("the peer disconnected (Disconnect-Peer-Request)");
        return;
    }
    if (h.app != APP_S6A || (h.cmd != CMD_CLR && h.cmd != CMD_IDR && h.cmd != CMD_DSR && h.cmd != CMD_RSR)) {
        answer(h, DIA_COMMAND_UNSUPPORTED, DiaBytes());
        return;
    }

    /* Requests of the HSS (TS 29.272 §7.2.7, §7.2.9, §7.2.11, §7.2.15). All
     * are accepted; a Cancel Location is remembered for the scenario. An
     * MME answers a Cancel Location for a user it does not know with
     * success as well (§5.2.1.2.3). */
    DiaAvp a;
    std::string imsi, session_id;
    if (dia_find(h.avps, h.avps_len, AVP_USER_NAME, 0, a)) {
        imsi.assign((const char *)a.data, a.len);
    }
    if (dia_find(h.avps, h.avps_len, AVP_SESSION_ID, 0, a)) {
        session_id.assign((const char *)a.data, a.len);
    }
    std::map<std::string, S6aSession *>::iterator it = by_imsi.find(imsi);
    const char *name = h.cmd == CMD_CLR ? "Cancel-Location" : h.cmd == CMD_IDR ? "Insert-Subscriber-Data" :
                       h.cmd == CMD_DSR ? "Delete-Subscriber-Data" : "Reset";
    if (h.cmd == CMD_CLR && it != by_imsi.end()) {
        uint32_t type = 0;
        find_u32(h.avps, h.avps_len, AVP_CANCELLATION_TYPE, VENDOR_3GPP, type);
        it->second->cancelled_ = true;
        it->second->cancellation_type_ = type;
        LOG_MSG("S6a %s: %s-Request from the HSS, Cancellation-Type %u\n", imsi.c_str(), name, type);
    } else {
        LOG_MSG("S6a %s: %s-Request from the HSS, answered%s\n", imsi.empty() ? "-" : imsi.c_str(),
                name, it == by_imsi.end() && h.cmd != CMD_RSR ? " (no such UE here)" : "");
    }
    DiaBytes extra, vsa;
    /* Session-Id comes first in an answer that has one (§8.8) */
    append(extra, dia_avp_str(AVP_SESSION_ID, 0, session_id));
    append(vsa, dia_avp_u32(AVP_VENDOR_ID, 0, VENDOR_3GPP));
    append(vsa, dia_avp_u32(AVP_AUTH_APPLICATION_ID, 0, APP_S6A));
    append(extra, dia_avp(AVP_VENDOR_SPECIFIC_APPLICATION_ID, 0, vsa));
    append(extra, dia_avp_u32(AVP_AUTH_SESSION_STATE, 0, AUTH_SESSION_STATE_NONE));
    answer(h, DIA_SUCCESS, extra);
}

void S6aEndpoint::receive()
{
    uint8_t buf[16384];
    for (int i = 0; i < 64 && fd >= 0; i++) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n == 0) {
            drop("closed by the peer");
            return;
        }
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                drop(strerror(errno));
            }
            break;
        }
        last_rx = clock_tick;
        rx.insert(rx.end(), buf, buf + n);
        DiaBytes msg;
        while (fd >= 0 && next_message(msg)) {
            handle(msg.data(), msg.size());
        }
    }
    if (fd < 0) {
        return;
    }
    if (watchdog_sent && clock_tick - watchdog_sent > S6A_WATCHDOG_MS) {
        drop("no answer to the Device-Watchdog-Request");
    } else if (!watchdog_sent && clock_tick - last_rx > S6A_WATCHDOG_MS) {
        /* Device-Watchdog-Request, RFC 6733 §5.5.1 */
        DiaBytes a;
        append(a, dia_avp_str(AVP_ORIGIN_HOST, 0, id.origin_host));
        append(a, dia_avp_str(AVP_ORIGIN_REALM, 0, id.origin_realm));
        append(a, dia_avp_u32(AVP_ORIGIN_STATE_ID, 0, start_time));
        watchdog_sent = clock_tick;
        send(dia_message(CMD_DWR, 0, FLAG_REQUEST, ++next_hbh, ++next_e2e, a));
    }
}

/* --- session ------------------------------------------------------------ */

S6aSession::S6aSession(const std::string &imsi) :
    imsi_(imsi), result_(0), cancelled_(false), cancellation_type_(0),
    pending_(0), pending_kind_(0), deadline_(0)
{
    S6aEndpoint::all.insert(this);
    S6aEndpoint::by_imsi[imsi_] = this;
}

S6aSession::~S6aSession()
{
    if (pending_) {
        S6aEndpoint::by_hbh.erase(pending_);
    }
    std::map<std::string, S6aSession *>::iterator it = S6aEndpoint::by_imsi.find(imsi_);
    if (it != S6aEndpoint::by_imsi.end() && it->second == this) {
        S6aEndpoint::by_imsi.erase(it);
    }
    S6aEndpoint::all.erase(this);
}

void S6aSession::fail(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    error_ = buf;
    WARNING("S6a %s: %s", imsi_.c_str(), buf);
    result_ = -1;
    if (pending_) {
        S6aEndpoint::by_hbh.erase(pending_);
        pending_ = 0;
    }
}

void S6aSession::send_request(int kind)
{
    error_.clear();
    result_ = 0;
    std::string err;
    if (!S6aEndpoint::open(err)) {
        fail("%s", err.c_str());
        return;
    }
    uint32_t hbh = ++S6aEndpoint::next_hbh, e2e = ++S6aEndpoint::next_e2e;
    /* S6a keeps no Diameter session state: every request is a session of
     * its own (TS 29.272 §7.1.4) */
    std::string sid = S6aEndpoint::new_session_id(imsi_);
    DiaBytes msg = kind == KIND_AIR ? s6a_encode_air(S6aEndpoint::id, sid, imsi_, hbh, e2e) :
                   kind == KIND_ULR ? s6a_encode_ulr(S6aEndpoint::id, sid, imsi_, imei_, hbh, e2e) :
                                      s6a_encode_pur(S6aEndpoint::id, sid, imsi_, hbh, e2e);
    pending_ = hbh;
    pending_kind_ = kind;
    deadline_ = clock_tick + s6a_timeout;
    S6aEndpoint::by_hbh[hbh] = this;
    if (!S6aEndpoint::send(msg) && pending_) {
        fail("cannot send to the Diameter peer");
    }
}

void S6aSession::authenticate()
{
    send_request(KIND_AIR);
}

void S6aSession::update_location(const std::string &apn, const std::string &imei)
{
    apn_ = apn;
    imei_ = imei;
    cancelled_ = false;
    send_request(KIND_ULR);
}

void S6aSession::purge()
{
    send_request(KIND_PUR);
}

void S6aSession::on_answer(const uint8_t *msg, size_t len)
{
    static const char *names[] = { "", "Authentication-Information", "Update-Location", "Purge-UE" };
    S6aEndpoint::by_hbh.erase(pending_);
    pending_ = 0;
    result_ = s6a_result_code(msg, len);
    if (result_ != DIA_SUCCESS) {
        char buf[96];
        snprintf(buf, sizeof(buf), "%s refused by the HSS, result %d", names[pending_kind_], result_);
        error_ = buf;
        WARNING("S6a %s: %s", imsi_.c_str(), buf);
        return;
    }
    if (pending_kind_ == KIND_ULR) {
        s6a_decode_subscription(msg, len, apn_, subscription_);
        const S6aSubscription &s = subscription_;
        if (s.apn_found) {
            LOG_MSG("S6a %s: location updated, MSISDN %s, APN %s: QCI %d, ARP %d, APN-AMBR %u/%u kbit/s, PDN type %d\n",
                    imsi_.c_str(), s.msisdn.c_str(), s.apn.c_str(), s.qci, s.arp, s.apn_ambr_ul,
                    s.apn_ambr_dl, s.pdn_type);
        } else {
            LOG_MSG("S6a %s: location updated, MSISDN %s, APN '%s' is not among the %d subscribed\n",
                    imsi_.c_str(), s.msisdn.c_str(), apn_.c_str(), s.apn_count);
        }
    }
}

void S6aSession::poll_all()
{
    if (S6aEndpoint::fd < 0) {
        return;
    }
    S6aEndpoint::receive();
    if (!S6aEndpoint::by_hbh.empty()) {
        std::vector<S6aSession *> late;
        for (std::map<uint32_t, S6aSession *>::iterator it = S6aEndpoint::by_hbh.begin();
             it != S6aEndpoint::by_hbh.end(); ++it) {
            if (clock_tick >= it->second->deadline_) {
                late.push_back(it->second);
            }
        }
        for (size_t i = 0; i < late.size(); i++) {
            late[i]->fail("no answer from the HSS within %d ms", s6a_timeout);
        }
    }
}

void S6aSession::shutdown_all()
{
    if (S6aEndpoint::fd < 0) {
        return;
    }
    /* Disconnect-Peer-Request with cause REBOOTING (§5.4.1), without
     * waiting for the answer */
    DiaBytes a;
    append(a, dia_avp_str(AVP_ORIGIN_HOST, 0, S6aEndpoint::id.origin_host));
    append(a, dia_avp_str(AVP_ORIGIN_REALM, 0, S6aEndpoint::id.origin_realm));
    append(a, dia_avp_u32(AVP_DISCONNECT_CAUSE, 0, 0));
    S6aEndpoint::send(dia_message(CMD_DPR, 0, FLAG_REQUEST, ++S6aEndpoint::next_hbh,
                                  ++S6aEndpoint::next_e2e, a));
    if (S6aEndpoint::fd >= 0) {
        close(S6aEndpoint::fd);
        S6aEndpoint::fd = -1;
    }
}

#ifdef GTEST
#include "gtest/gtest.h"

static DiaBytes hexbytes(const char *hex)
{
    DiaBytes out;
    for (size_t i = 0; hex[i] && hex[i + 1]; i += 2) {
        unsigned int b;
        sscanf(hex + i, "%2x", &b);
        out.push_back(b);
    }
    return out;
}

static S6aIdentity test_identity()
{
    S6aIdentity id;
    id.origin_host = "mme.epc.mnc001.mcc001.3gppnetwork.org";
    id.origin_realm = "epc.mnc001.mcc001.3gppnetwork.org";
    id.dest_realm = "epc.mnc024.mcc262.3gppnetwork.org";
    id.visited_plmn = "00101";
    return id;
}

/* A peer finds the next AVP by the length rounded up to 4 octets, while the
 * length field itself leaves the padding out: get either wrong and every
 * AVP after an odd-sized one is misread. */
TEST(S6a, AvpHeaderLengthAndPadding) {
    EXPECT_EQ(hexbytes("00000108" "40" "00000b" "616263" "00"), dia_avp_str(264, 0, "abc"));
    /* vendor-specific: V bit and the Vendor-Id in front of the data */
    EXPECT_EQ(hexbytes("0000057d" "c0" "000010" "000028af" "00000022"),
              dia_avp_u32(1405, 10415, 34));
    EXPECT_EQ(hexbytes("00000408" "80" "000010" "000028af" "000003ec"),
              dia_avp_u32(1032, 10415, 1004, false));
}

TEST(S6a, DerivesMmeNameAndRealmFromThePlmn) {
    EXPECT_EQ("epc.mnc001.mcc001.3gppnetwork.org", s6a_default_realm("00101"));
    EXPECT_EQ("epc.mnc410.mcc310.3gppnetwork.org", s6a_default_realm("310410"));
    EXPECT_EQ("mmec01.mmegi0001.mme.epc.mnc024.mcc262.3gppnetwork.org", s6a_default_host("26224"));
    EXPECT_EQ("", s6a_default_realm("123"));
}

/* The HSS decides on roaming from Visited-PLMN-Id and routes its own
 * requests back by Origin-Host; the DRA routes by Destination-Realm and
 * application. A ULR missing one of these is not answered usefully. */
TEST(S6a, UpdateLocationRequestCarriesWhatHssAndDraNeed) {
    DiaBytes m = s6a_encode_ulr(test_identity(), "mme;1;2;001010000000001", "001010000000001",
                                "3560920407905401", 0x11, 0x22);
    DiaHeader h;
    DiaAvp a;
    ASSERT_TRUE(dia_decode_header(m.data(), m.size(), h));
    EXPECT_EQ(316u, h.cmd);
    EXPECT_EQ(16777251u, h.app);
    EXPECT_TRUE(h.request);
    EXPECT_TRUE(h.proxiable);           /* or a DRA must not relay it */
    EXPECT_EQ(0x11u, h.hop_by_hop);
    EXPECT_EQ(m.size(), (size_t)get24(m.data() + 1));

    ASSERT_TRUE(dia_find(h.avps, h.avps_len, 1, 0, a));
    EXPECT_EQ("001010000000001", std::string((const char *)a.data, a.len));
    ASSERT_TRUE(dia_find(h.avps, h.avps_len, 283, 0, a));
    EXPECT_EQ("epc.mnc024.mcc262.3gppnetwork.org", std::string((const char *)a.data, a.len));
    ASSERT_TRUE(dia_find(h.avps, h.avps_len, 1407, 10415, a));
    EXPECT_EQ(hexbytes("00f110"), DiaBytes(a.data, a.data + a.len));   /* 001/01 */
    uint32_t v = 0;
    ASSERT_TRUE(find_u32(h.avps, h.avps_len, 1405, 10415, v));
    EXPECT_EQ(0x22u, v);                /* S6a indicator and initial attach */
    ASSERT_TRUE(find_u32(h.avps, h.avps_len, 1032, 10415, v));
    EXPECT_EQ(1004u, v);
    ASSERT_TRUE(find_u32(h.avps, h.avps_len, 277, 0, v));
    EXPECT_EQ(1u, v);
    ASSERT_TRUE(dia_find(h.avps, h.avps_len, 1401, 10415, a));
    DiaAvp imei, sv;
    ASSERT_TRUE(dia_find(a.data, a.len, 1402, 10415, imei));
    EXPECT_EQ("35609204079054", std::string((const char *)imei.data, imei.len));
    ASSERT_TRUE(dia_find(a.data, a.len, 1403, 10415, sv));
    EXPECT_EQ("01", std::string((const char *)sv.data, sv.len));
}

TEST(S6a, AuthenticationInformationRequestAsksForOneEutranVector) {
    DiaBytes m = s6a_encode_air(test_identity(), "s", "001010000000001", 1, 2);
    DiaHeader h;
    DiaAvp a;
    uint32_t v = 0;
    ASSERT_TRUE(dia_decode_header(m.data(), m.size(), h));
    EXPECT_EQ(318u, h.cmd);
    ASSERT_TRUE(dia_find(h.avps, h.avps_len, 1408, 10415, a));
    ASSERT_TRUE(find_u32(a.data, a.len, 1410, 10415, v));
    EXPECT_EQ(1u, v);
    EXPECT_TRUE(dia_find(h.avps, h.avps_len, 1407, 10415, a));
}

/* An Update Location Answer as an HSS builds it: MSISDN, UE-AMBR and a
 * profile with two APNs. The Create Session Request is filled from the IMS
 * APN's values, so taking the first APN's (or the UE-AMBR) would ask the PGW
 * for the wrong bearer. */
static DiaBytes test_ula(bool with_data)
{
    DiaBytes a, sub, profile;
    append(a, dia_avp_str(263, 0, "s"));
    append(a, dia_avp_u32(268, 0, 2001));
    if (with_data) {
        DiaBytes ue_ambr, internet, ims, qos, arp, apn_ambr;
        append(sub, dia_avp(701, 10415, hexbytes("945155009900f1")));
        append(ue_ambr, dia_avp_u32(516, 10415, 50000000));
        append(ue_ambr, dia_avp_u32(515, 10415, 100000000));
        append(sub, dia_avp(1435, 10415, ue_ambr));

        append(arp, dia_avp_u32(1046, 10415, 8));
        append(qos, dia_avp_u32(1028, 10415, 9));
        append(qos, dia_avp(1034, 10415, arp));
        append(internet, dia_avp_str(493, 0, "internet"));
        append(internet, dia_avp_u32(1456, 10415, 2));
        append(internet, dia_avp(1431, 10415, qos));

        arp.clear(); qos.clear();
        append(arp, dia_avp_u32(1046, 10415, 2));
        append(qos, dia_avp_u32(1028, 10415, 5));
        append(qos, dia_avp(1034, 10415, arp));
        append(apn_ambr, dia_avp_u32(516, 10415, 256000));
        append(apn_ambr, dia_avp_u32(515, 10415, 512000));
        append(ims, dia_avp_u32(1423, 10415, 2));
        append(ims, dia_avp_u32(1456, 10415, 0));
        append(ims, dia_avp_str(493, 0, "ims"));
        append(ims, dia_avp(1431, 10415, qos));
        append(ims, dia_avp(1435, 10415, apn_ambr));

        append(profile, dia_avp_u32(1423, 10415, 1));
        append(profile, dia_avp(1430, 10415, internet));
        append(profile, dia_avp(1430, 10415, ims));
        append(sub, dia_avp(1429, 10415, profile));
        append(a, dia_avp(1400, 10415, sub));
    }
    return dia_message(316, 16777251, FLAG_PROXIABLE, 1, 2, a);
}

TEST(S6a, SubscriptionDataOfTheRequestedApn) {
    DiaBytes ula = test_ula(true);
    S6aSubscription s;
    EXPECT_EQ(2001, s6a_result_code(ula.data(), ula.size()));
    ASSERT_TRUE(s6a_decode_subscription(ula.data(), ula.size(), "ims", s));
    EXPECT_EQ("4915550099001", s.msisdn);
    EXPECT_EQ(2, s.apn_count);
    EXPECT_TRUE(s.apn_found);
    EXPECT_EQ(5, s.qci);
    EXPECT_EQ(2, s.arp);
    EXPECT_EQ(0, s.pdn_type);
    EXPECT_EQ(256u, s.apn_ambr_ul);     /* kbit/s, not the UE-AMBR */
    EXPECT_EQ(512u, s.apn_ambr_dl);
    EXPECT_EQ(50000u, s.ue_ambr_ul);

    ASSERT_TRUE(s6a_decode_subscription(ula.data(), ula.size(), "mms", s));
    EXPECT_FALSE(s.apn_found);          /* the scenario can tell */
    EXPECT_EQ(2, s.apn_count);

    DiaBytes bare = test_ula(false);
    EXPECT_FALSE(s6a_decode_subscription(bare.data(), bare.size(), "ims", s));
}

/* "Roaming not allowed" is an S6a error, sent as Experimental-Result. A
 * scenario that expects 5004 must see 5004, not "no result". */
TEST(S6a, ExperimentalResultCodeIsTheResult) {
    DiaBytes a, exp;
    append(exp, dia_avp_u32(266, 0, 10415));
    append(exp, dia_avp_u32(298, 0, 5004));
    append(a, dia_avp(297, 0, exp));
    DiaBytes m = dia_message(316, 16777251, FLAG_PROXIABLE, 1, 2, a);
    EXPECT_EQ(5004, s6a_result_code(m.data(), m.size()));
    DiaBytes none = dia_message(316, 16777251, 0, 1, 2, DiaBytes());
    EXPECT_EQ(0, s6a_result_code(none.data(), none.size()));
}

TEST(S6a, BrokenMessagesAreRefused) {
    DiaBytes m = s6a_encode_pur(test_identity(), "s", "001010000000001", 1, 2);
    DiaHeader h;
    DiaAvp a;
    EXPECT_FALSE(dia_decode_header(m.data(), 19, h));
    EXPECT_FALSE(dia_decode_header(m.data(), m.size() - 1, h));
    m[0] = 2;                           /* not Diameter version 1 */
    EXPECT_FALSE(dia_decode_header(m.data(), m.size(), h));
    /* an AVP whose length runs past the end is not followed */
    DiaBytes bad = hexbytes("00000108" "40" "0000ff" "6162");
    EXPECT_FALSE(dia_find(bad.data(), bad.size(), 264, 0, a));
}
#endif /* GTEST */

#endif /* USE_S8 */
