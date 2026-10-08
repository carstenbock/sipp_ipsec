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
 *  SWu client for VoWiFi (3GPP TS 24.302 / TS 33.402): the UE side of the
 *  IKEv2 tunnel to an ePDG, authenticated with EAP-AKA' (RFC 5448) or
 *  EAP-AKA (RFC 4187), whichever the AAA server starts.
 *  One SwuSession is one UE's tunnel; a call owns at most one.
 */

#ifndef __SWU_HPP__
#define __SWU_HPP__

#ifdef USE_SWU

#include <stdint.h>
#include <string>
#include <vector>

typedef std::vector<uint8_t> SwuBytes;

/* --- Key derivation, exposed for the unit tests ------------------------- */

/* CK', IK' (RFC 5448 §3.3, TS 33.402 Annex A.2) */
void swu_aka_prime_ckik(const uint8_t ck[16], const uint8_t ik[16],
                        const std::string &network_name,
                        const uint8_t sqn_xor_ak[6],
                        uint8_t ck_prime[16], uint8_t ik_prime[16]);

struct SwuAkaPrimeKeys {
    uint8_t k_encr[16];
    uint8_t k_aut[32];
    uint8_t k_re[32];
    uint8_t msk[64];
    uint8_t emsk[64];
};

/* MK = PRF'(IK'|CK', "EAP-AKA'"|Identity), split per RFC 5448 §3.3 */
void swu_aka_prime_keys(const uint8_t ck_prime[16], const uint8_t ik_prime[16],
                        const std::string &identity, SwuAkaPrimeKeys &out);

/* EAP-AKA (RFC 4187 §7): MK = SHA1(Identity|IK|CK), expanded with the
 * FIPS 186-2 generator */
struct SwuAkaKeys {
    uint8_t k_encr[16];
    uint8_t k_aut[16];
    uint8_t msk[64];
    uint8_t emsk[64];
};
void swu_aka_keys(const uint8_t ck[16], const uint8_t ik[16],
                  const std::string &identity, SwuAkaKeys &out);
void swu_fips186_prf(const uint8_t mk[20], uint8_t *out, size_t len);

/* IKEv2 prf+ with PRF_HMAC_SHA2_256 (RFC 7296 §2.13) */
SwuBytes swu_prf_plus(const SwuBytes &key, const SwuBytes &seed, size_t len);

/* --- Session ------------------------------------------------------------ */

enum SwuState {
    SWU_IDLE = 0,
    SWU_INIT_SENT,      /* waiting for IKE_SA_INIT response */
    SWU_AUTH_EAP,       /* IKE_AUTH, EAP rounds */
    SWU_AUTH_FINAL,     /* IKE_AUTH with AUTH sent, waiting for CFG_REPLY */
    SWU_ESTABLISHED,
    SWU_DELETING,       /* our Delete sent, waiting for the response */
    SWU_CLOSED,
    SWU_FAILED
};

struct SwuConfig {
    std::string epdg;       /* ePDG address (IPv4) */
    std::string local_ip;   /* our outer address, empty = let the kernel choose */
    std::string identity;   /* NAI: <d><IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org,
                               d = 6 for EAP-AKA', 0 for EAP-AKA (TS 23.003 §19.3.2) */
    std::string apn;        /* sent as IDr */
    int pdn_type;           /* inner addresses asked for: 1 IPv4, 2 IPv6, 3 both */
    int sip_family;         /* address family for SIP: 0 IPv6 if there is a
                               P-CSCF for it (GSMA IR.92), 4 or 6 */
    uint8_t k[16];
    uint8_t opc[16];
};

class SwuSession {
public:
    explicit SwuSession(const SwuConfig &cfg);
    ~SwuSession();

    /* Send IKE_SA_INIT. Progress is driven by poll_all(). */
    int start();
    /* Send Delete for the IKE SA; the session is CLOSED once answered. */
    void detach();

    SwuState state() const { return state_; }
    bool busy() const {
        return state_ == SWU_INIT_SENT || state_ == SWU_AUTH_EAP ||
               state_ == SWU_AUTH_FINAL || state_ == SWU_DELETING;
    }
    const char *error() const { return error_.c_str(); }

    /* Valid once ESTABLISHED */
    /* The inner address SIP uses, and the P-CSCF for it (may be empty) */
    const char *inner_ip() const { return sip_ip_.c_str(); }
    const char *pcscf() const { return sip_pcscf_.c_str(); }
    /* Every inner address the ePDG assigned; empty if none of that family */
    const char *inner_ip4() const { return inner_ip_.c_str(); }
    const char *inner_ip6() const { return inner_ip6_.c_str(); }
    const char *outer_local() const { return outer_local_.c_str(); }
    const char *outer_remote() const { return cfg_.epdg.c_str(); }
    uint32_t reqid() const { return reqid_; }

    /* Receive and time out for all sessions; called from the main loop. */
    static void poll_all();
    /* Delete every remaining tunnel (process exit). */
    static void shutdown_all();

private:
    struct Payload {
        uint8_t type;
        SwuBytes body;
    };

    void on_readable();
    void on_timer();
    void on_datagram(const uint8_t *data, size_t len);
    void on_response(uint8_t exchange, uint8_t first, const uint8_t *msg, size_t len);
    void on_request(uint8_t exchange, uint32_t msgid, uint8_t first, const uint8_t *msg, size_t len);

    void handle_init_response(uint8_t first, const uint8_t *msg, size_t len);
    void handle_auth_response(const std::vector<Payload> &pls);
    bool handle_eap(const SwuBytes &eap, SwuBytes &reply, bool &success);
    bool handle_aka_challenge(const SwuBytes &eap, SwuBytes &reply);
    void finish_auth(const std::vector<Payload> &pls);

    SwuBytes build_init();
    void send_auth_first();
    void send_request(uint8_t exchange, const std::vector<Payload> &pls, bool encrypt);
    SwuBytes build_msg(uint8_t exchange, uint8_t flags, uint32_t msgid,
                       const std::vector<Payload> &pls, bool encrypt);
    bool decrypt(uint8_t first, const uint8_t *msg, size_t len, std::vector<Payload> &out);
    void transmit(const SwuBytes &msg);
    bool float_to_natt();

    void derive_ike_keys(const SwuBytes &shared);
    SwuBytes auth_octets(bool initiator);
    int install_kernel();
    void remove_kernel();
    void fail(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
    void set_pending(bool pending);

    SwuConfig cfg_;
    SwuState state_;
    std::string error_;
    int fd_;

    uint8_t spi_i_[8], spi_r_[8];
    SwuBytes nonce_i_, nonce_r_;
    SwuBytes dh_priv_, dh_pub_;
    SwuBytes cookie_;
    SwuBytes init_req_, init_resp_;     /* raw messages, signed in AUTH */
    SwuBytes sk_d_, sk_ai_, sk_ar_, sk_ei_, sk_er_, sk_pi_, sk_pr_;
    SwuBytes idi_body_, idr_body_;
    SwuBytes msk_;
    uint32_t child_spi_i_, child_spi_r_;    /* ESP SPIs: ours (inbound), ePDG's (outbound) */

    uint32_t next_msgid_;       /* of our next request */
    SwuBytes pending_;          /* our unanswered request, for retransmission */
    unsigned long retrans_at_;
    int retrans_count_;
    uint32_t last_peer_msgid_;  /* last ePDG request we answered */
    SwuBytes last_peer_reply_;

    bool natt_;                 /* moved to UDP 4500 (after IKE_SA_INIT) */
    std::string outer_local_;
    uint16_t outer_port_;
    std::string inner_ip_, pcscf_;          /* IPv4 */
    std::string inner_ip6_, pcscf6_;        /* IPv6 */
    std::string sip_ip_, sip_pcscf_;
    uint32_t reqid_;
    bool sa_out_, sa_in_, pol_out_, pol_in_, addr_;
    bool pol6_out_, pol6_in_, addr6_;
};

#endif /* USE_SWU */
#endif /* __SWU_HPP__ */
