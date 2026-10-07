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
 *  S6a (3GPP TS 29.272, Diameter base protocol RFC 6733): SIPp as the
 *  visited MME toward the home HSS, usually through a DRA, for S8
 *  home-routed roaming tests. One S6aSession is one UE's registration at
 *  the HSS; a call owns at most one. All sessions share one Diameter
 *  connection.
 */

#ifndef __S6A_HPP__
#define __S6A_HPP__

#ifdef USE_S8

#include <stdint.h>
#include <string>
#include <vector>

typedef std::vector<uint8_t> DiaBytes;

/* Result codes used here: RFC 6733 §7.1, TS 29.272 §7.4 (experimental) */
enum {
    DIA_SUCCESS = 2001,
    DIA_COMMAND_UNSUPPORTED = 3001,
    DIA_ERROR_USER_UNKNOWN = 5001,              /* experimental, TS 29.272 §7.4.3.1 */
    DIA_ERROR_ROAMING_NOT_ALLOWED = 5004        /* experimental, TS 29.272 §7.4.3.3 */
};

/* --- Codec, exposed for the unit tests ---------------------------------- */

struct DiaHeader {
    uint32_t cmd, app;
    uint32_t hop_by_hop, end_to_end;
    bool request, proxiable, error;
    const uint8_t *avps;
    size_t avps_len;
};

struct DiaAvp {
    uint32_t code, vendor;      /* vendor 0: no Vendor-Id in the AVP */
    uint8_t flags;
    const uint8_t *data;
    size_t len;
};

/* One AVP with its header and padding (RFC 6733 §4.1). vendor != 0 sets the V bit. */
DiaBytes dia_avp(uint32_t code, uint32_t vendor, const DiaBytes &data, bool mandatory = true);
DiaBytes dia_avp_u32(uint32_t code, uint32_t vendor, uint32_t value, bool mandatory = true);
DiaBytes dia_avp_str(uint32_t code, uint32_t vendor, const std::string &value, bool mandatory = true);
/* A whole message (RFC 6733 §3) */
DiaBytes dia_message(uint32_t cmd, uint32_t app, uint8_t flags, uint32_t hop_by_hop,
                     uint32_t end_to_end, const DiaBytes &avps);
/* msg is a whole message; false if it cannot be a Diameter message */
bool dia_decode_header(const uint8_t *msg, size_t len, DiaHeader &h);
/* First AVP with this code and vendor among the AVPs in [avps, avps+len) */
bool dia_find(const uint8_t *avps, size_t len, uint32_t code, uint32_t vendor, DiaAvp &out);

/* Who we are and where requests go */
struct S6aIdentity {
    std::string origin_host, origin_realm;
    std::string dest_realm;     /* the home network's realm */
    std::string visited_plmn;   /* "<mcc><mnc>" */
};

/* MME node name and realm for a PLMN (TS 23.003 §19.4.2.4, §19.2) */
std::string s6a_default_host(const std::string &mccmnc);
std::string s6a_default_realm(const std::string &mccmnc);

/* What the Subscription-Data of an Update Location Answer said, for one APN */
struct S6aSubscription {
    std::string msisdn;         /* digits */
    int apn_count;              /* APN configurations in the profile */
    bool apn_found;             /* the APN asked for is one of them */
    std::string apn;
    int pdn_type;               /* 0 IPv4, 1 IPv6, 2 IPv4v6, 3 IPv4 or IPv6 */
    int qci;
    int arp;                    /* priority level */
    uint32_t apn_ambr_ul, apn_ambr_dl;  /* kbit/s, as GTPv2 wants them */
    uint32_t ue_ambr_ul, ue_ambr_dl;    /* kbit/s */

    S6aSubscription() : apn_count(0), apn_found(false), pdn_type(0), qci(0), arp(0),
        apn_ambr_ul(0), apn_ambr_dl(0), ue_ambr_ul(0), ue_ambr_dl(0) {}
};

DiaBytes s6a_encode_air(const S6aIdentity &id, const std::string &session_id,
                        const std::string &imsi, uint32_t hop_by_hop, uint32_t end_to_end);
DiaBytes s6a_encode_ulr(const S6aIdentity &id, const std::string &session_id,
                        const std::string &imsi, const std::string &imei,
                        uint32_t hop_by_hop, uint32_t end_to_end);
DiaBytes s6a_encode_pur(const S6aIdentity &id, const std::string &session_id,
                        const std::string &imsi, uint32_t hop_by_hop, uint32_t end_to_end);
/* Result-Code, or the Experimental-Result-Code if that is what the answer
 * carries; 0 if it has neither */
int s6a_result_code(const uint8_t *msg, size_t len);
/* Subscription-Data of an Update Location Answer; false if there is none */
bool s6a_decode_subscription(const uint8_t *msg, size_t len, const std::string &apn,
                             S6aSubscription &out);

/* --- Session ------------------------------------------------------------ */

class S6aSession {
public:
    explicit S6aSession(const std::string &imsi);
    ~S6aSession();

    /* Each sends one request; progress is driven by poll_all(). */
    void authenticate();                                        /* AIR */
    void update_location(const std::string &apn, const std::string &imei);  /* ULR */
    void purge();                                               /* PUR */

    bool busy() const { return pending_ != 0; }
    /* Result of the last answer; -1 when none came (or no connection) */
    int result() const { return result_; }
    const char *error() const { return error_.c_str(); }
    const S6aSubscription &subscription() const { return subscription_; }

    /* The HSS cancelled the registration (Cancel Location Request) */
    bool cancelled() const { return cancelled_; }
    int cancellation_type() const { return cancellation_type_; }

    /* Receive, answer the peer's requests, time out; from the main loop. */
    static void poll_all();
    /* Close the connection (process exit). */
    static void shutdown_all();

private:
    friend class S6aEndpoint;

    void send_request(int kind);
    void on_answer(const uint8_t *msg, size_t len);
    void fail(const char *fmt, ...) __attribute__((format(printf, 2, 3)));

    std::string imsi_, apn_, imei_;
    int result_;
    std::string error_;
    S6aSubscription subscription_;
    bool cancelled_;
    int cancellation_type_;

    uint32_t pending_;          /* hop-by-hop id of our unanswered request, or 0 */
    int pending_kind_;
    unsigned long deadline_;
};

#endif /* USE_S8 */
#endif /* __S6A_HPP__ */
