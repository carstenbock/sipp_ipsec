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
 *  S8 control plane (GTPv2-C, 3GPP TS 29.274): SIPp as the S8 side of a
 *  visited SGW toward a home PGW, for S8 home-routed roaming tests. One
 *  S8Session is one UE's PDN connection; a call owns at most one. All
 *  sessions share one endpoint on UDP 2123.
 */

#ifndef __GTPC_HPP__
#define __GTPC_HPP__

#ifdef USE_S8

#include <stdint.h>
#include <map>
#include <string>
#include <vector>

#include "gtpu.hpp"

typedef std::vector<uint8_t> GtpBytes;

/* GTPv2 cause values used here (TS 29.274 Table 8.4-1) */
enum {
    GTP_CAUSE_ACCEPTED = 16,
    GTP_CAUSE_CONTEXT_NOT_FOUND = 64,
    GTP_CAUSE_NO_RESOURCES = 73,
    GTP_CAUSE_REQUEST_REJECTED = 94
};

/* --- Codec, exposed for the unit tests ---------------------------------- */

/* TBCD digits (TS 29.274 §8.3: IMSI, §8.11: MSISDN), odd length filled with 0xF */
GtpBytes gtp_tbcd(const std::string &digits);
/* PLMN id from "<mcc><mnc>" with a 2- or 3-digit MNC (§8.18) */
bool gtp_plmn(const std::string &mccmnc, uint8_t out[3]);
/* APN as length-prefixed labels (§8.6, TS 23.003 §9.1) */
GtpBytes gtp_apn(const std::string &apn);

struct S8Config {
    std::string imsi;
    std::string msisdn;         /* digits, a leading '+' is dropped */
    std::string mei;            /* IMEI(SV), optional */
    std::string apn;
    std::string plmn;           /* visited PLMN: Serving Network and ULI */
    std::string local_ip;       /* address in our F-TEIDs */
    int qci;
    int arp;                    /* priority level 1..15 */
    uint32_t ambr_ul, ambr_dl;  /* APN-AMBR in kbit/s */
    uint16_t tac;
    uint32_t eci;
};

/* What a Create Session Response told us */
struct S8Result {
    int cause;                  /* 0 when the response had no Cause IE */
    std::string ue_ip, pcscf;
    std::string pgw_c_ip, pgw_u_ip;
    uint32_t pgw_c_teid, pgw_u_teid;
};

GtpBytes gtp_encode_create_session(const S8Config &cfg, uint32_t seq,
                                   uint32_t c_teid, uint32_t u_teid, uint8_t recovery);
/* msg is a whole GTPv2 message; false if it cannot be parsed */
bool gtp_decode_create_session_response(const uint8_t *msg, size_t len, S8Result &out);

/* --- Dedicated bearers -------------------------------------------------- */

/* TFT operation codes (TS 24.008 §10.5.6.12) */
enum {
    TFT_CREATE = 1, TFT_DELETE = 2, TFT_ADD_FILTERS = 3,
    TFT_REPLACE_FILTERS = 4, TFT_DELETE_FILTERS = 5, TFT_NO_OPERATION = 6
};

struct GtpTftFilter {
    uint8_t id;                 /* packet filter identifier, 0..15 */
    uint8_t direction;          /* 0 pre Rel-7, 1 downlink, 2 uplink, 3 both */
    GtpuFilter match;
};

/*
 * Decode a Bearer TFT IE's value (TS 29.274 §8.19, coded as TS 24.008
 * §10.5.6.12). For TFT_DELETE_FILTERS the filters carry only their id.
 * False if the TFT is malformed.
 */
bool gtp_decode_tft(const uint8_t *v, size_t len, int &opcode,
                    std::vector<GtpTftFilter> &filters);
/* Apply a decoded TFT operation to the filters a bearer has. */
void gtp_apply_tft(std::vector<GtpTftFilter> &current, int opcode,
                   const std::vector<GtpTftFilter> &filters);
/* The filters that select uplink packets, as the user plane wants them */
std::vector<GtpuFilter> gtp_uplink_filters(const std::vector<GtpTftFilter> &tft);

/* One bearer context of a Create or Update Bearer Request */
struct GtpBearerRequest {
    int ebi;                    /* 0 in a Create Bearer Request */
    int qci;                    /* 0 if no Bearer QoS was given */
    bool has_tft, tft_ok;
    int tft_opcode;
    std::vector<GtpTftFilter> tft;
    std::string pgw_u_ip;
    uint32_t pgw_u_teid;
};

/* ies: the IEs of a Create Bearer Request (Table 7.2.3-1) or an Update
 * Bearer Request (Table 7.2.15-1); false on a broken TLV */
bool gtp_decode_bearer_request(const uint8_t *ies, size_t len, int &linked_ebi,
                               std::vector<GtpBearerRequest> &bearers);

/* A dedicated bearer of a session */
struct S8Bearer {
    int ebi;
    int qci;
    uint32_t local_teid;        /* ours, for downlink */
    uint32_t pgw_u_teid;
    std::string pgw_u_ip;
    std::vector<GtpTftFilter> tft;
};

/* --- Session ------------------------------------------------------------ */

enum S8State {
    S8_IDLE = 0,
    S8_CREATING,        /* Create Session Request sent */
    S8_ACTIVE,
    S8_DELETING,        /* Delete Session Request sent */
    S8_CLOSED,
    S8_FAILED           /* rejected by the PGW, or no answer */
};

class S8Session {
public:
    explicit S8Session(const S8Config &cfg);
    ~S8Session();

    /* Send the Create Session Request. Progress is driven by poll_all(). */
    int create();
    /* Send the Delete Session Request; CLOSED once answered. */
    void remove();

    S8State state() const { return state_; }
    bool busy() const { return state_ == S8_CREATING || state_ == S8_DELETING; }
    const char *error() const { return error_.c_str(); }
    /* GTP cause of the last response; -1 when the PGW did not answer */
    int cause() const { return result_.cause; }
    const S8Result &result() const { return result_; }

    /* Dedicated bearers the PGW has created and not yet deleted */
    const std::vector<S8Bearer> &bearers() const { return bearers_; }
    /* EBI of a dedicated bearer with this QCI (0: any QCI); 0 if there is none */
    int dedicated_bearer(int qci) const;

    /* Receive and time out for all sessions; called from the main loop. */
    static void poll_all();
    /* Delete every remaining session (process exit). */
    static void shutdown_all();

private:
    friend class GtpcEndpoint;

    void send_request(uint8_t type, uint32_t teid, const GtpBytes &ies);
    void on_response(uint8_t type, const uint8_t *msg, size_t len);
    void on_request(uint8_t type, uint32_t seq, const uint8_t *ies, size_t len,
                    const struct sockaddr_in &from);
    void on_timer();
    void fail(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
    void release_user_plane();
    GtpBytes create_bearers(const uint8_t *ies, size_t len);
    GtpBytes update_bearers(const uint8_t *ies, size_t len);
    GtpBytes delete_bearers(const uint8_t *ies, size_t len, bool &session_deleted);
    void drop_bearer(size_t index, const char *why);

    S8Config cfg_;
    S8State state_;
    std::string error_;
    S8Result result_;
    uint32_t c_teid_, u_teid_;      /* ours */
    bool user_plane_;
    std::vector<S8Bearer> bearers_;
    /* Our answers to the PGW's last requests, by sequence number: a
     * retransmitted request gets the same answer again and is not carried
     * out a second time (TS 29.274 §7.6) */
    std::map<uint32_t, GtpBytes> answered_;

    GtpBytes pending_;              /* our unanswered request */
    uint32_t pending_seq_;
    unsigned long retrans_at_;
    int retrans_count_;
};

#endif /* USE_S8 */
#endif /* __GTPC_HPP__ */
