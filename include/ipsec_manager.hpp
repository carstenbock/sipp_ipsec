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
 *  IPSec Manager for VoLTE / IMS (3GPP TS 33.203).
 *  Manages the lifecycle of IPSec Security Associations for the UE side
 *  of the IMS registration flow.
 */

#ifndef __IPSEC_MANAGER_HPP__
#define __IPSEC_MANAGER_HPP__

#ifdef USE_IPSEC

#include <stdint.h>
#include <string>

/* Default protected port range for UE */
#define IPSEC_DEFAULT_PORT_C  5060
#define IPSEC_DEFAULT_PORT_S  5061

/* IPSec negotiation state */
enum IPSecState {
    IPSEC_STATE_IDLE = 0,
    IPSEC_STATE_PARAMS_ALLOCATED,
    IPSEC_STATE_SA_ESTABLISHED,
    IPSEC_STATE_ACTIVE,
    IPSEC_STATE_TORN_DOWN
};

/* Algorithms as negotiated in Security-Client/Server headers (3GPP names) */
struct IPSecAlgorithms {
    char aalg[64];      /* 3GPP name, e.g. "hmac-sha-1-96" */
    char ealg[64];      /* 3GPP name, e.g. "aes-cbc" or "null" */
};

/* Per-call IPSec parameters */
struct IPSecParams {
    /* UE (local) side */
    uint32_t spi_uc;            /* SPI for UE client (outbound from port_uc) */
    uint32_t spi_us;            /* SPI for UE server (inbound to port_us) */
    uint16_t port_uc;           /* UE protected client port */
    uint16_t port_us;           /* UE protected server port */

    /* P-CSCF (remote) side -- filled from Security-Server header */
    uint32_t spi_pc;            /* SPI for P-CSCF client */
    uint32_t spi_ps;            /* SPI for P-CSCF server */
    uint16_t port_pc;           /* P-CSCF protected client port */
    uint16_t port_ps;           /* P-CSCF protected server port */

    /* Crypto keys from AKA */
    unsigned char ck[16];       /* Cipher Key (128 bits) */
    unsigned char ik[16];       /* Integrity Key (128 bits) */

    /* Negotiated algorithms */
    IPSecAlgorithms algos;

    /* IP addresses */
    char local_ip[64];
    char remote_ip[64];

    /* Upper-layer protocol */
    int proto;                  /* IPPROTO_UDP or IPPROTO_TCP */

    /* State tracking */
    IPSecState state;
};

class IPSecManager {
public:
    IPSecManager();
    ~IPSecManager();

    /**
     * Initialize the XFRM subsystem.
     * Must be called once before any SA operations.
     * @return 0 on success, -1 on error.
     */
    int init();

    /**
     * Allocate local IPSec parameters: generate random SPIs and assign ports.
     * Called before sending the initial REGISTER (to populate Security-Client).
     *
     * @param params  Output: filled with spi_uc, spi_us, port_uc, port_us
     * @param port_c  Local client port to use (0 for random ephemeral)
     * @param port_s  Local server port to use (0 for random ephemeral)
     * @return 0 on success
     */
    int allocate_local_params(IPSecParams &params, uint16_t port_c = 0, uint16_t port_s = 0);

    /**
     * Set the crypto keys derived from AKA authentication.
     * Called after processing the 401 response and running AKA.
     *
     * @param params   Params to update with keys
     * @param ck       Cipher Key (16 bytes)
     * @param ik       Integrity Key (16 bytes)
     */
    void set_keys(IPSecParams &params, const unsigned char *ck, const unsigned char *ik);

    /**
     * Establish the 4 IPSec Security Associations and Security Policies.
     * Called after AKA and after parsing the Security-Server header (which
     * provides spi_pc, spi_ps, port_pc, port_ps).
     *
     * The 4 SA pairs are:
     *   1. UE:port_uc -> PCSCF:port_ps  (SPI = spi_ps, outbound)
     *   2. PCSCF:port_ps -> UE:port_uc  (SPI = spi_uc, inbound) -- responses
     *   3. PCSCF:port_pc -> UE:port_us  (SPI = spi_us, inbound)
     *   4. UE:port_us -> PCSCF:port_pc  (SPI = spi_pc, outbound) -- responses
     *
     * @param params  Fully populated IPSecParams
     * @return 0 on success, -1 on error
     */
    int setup_security_associations(IPSecParams &params);

    /**
     * Tear down all 4 SAs and SPs.
     * Called on deregistration or error.
     *
     * @param params  The params that were used to set up the SAs
     * @return 0 on success, -1 on error
     */
    int teardown_security_associations(IPSecParams &params);

    /**
     * Map 3GPP algorithm names to Linux XFRM algorithm names.
     */
    static const char *aalg_to_xfrm(const char *aalg_3gpp);
    static const char *ealg_to_xfrm(const char *ealg_3gpp);
    static int aalg_key_bits(const char *aalg_3gpp);
    static int ealg_key_bits(const char *ealg_3gpp);

private:
    bool initialized_;
    uint32_t generate_spi();

    int setup_sa_pair(const IPSecParams &params,
                      const char *src, const char *dst,
                      uint16_t src_port, uint16_t dst_port,
                      uint32_t spi);
    int setup_policy_pair(const IPSecParams &params,
                          const char *src, const char *dst,
                          uint16_t src_port, uint16_t dst_port,
                          uint32_t spi, int dir);
};

/*
 * Global IPSec configuration variables.
 * Declared in sipp.hpp via MAYBE_EXTERN:
 *   - ipsec_enabled  (bool)
 *   - ipsec_aalg     (const char *)
 *   - ipsec_ealg     (const char *)
 */

#endif /* USE_IPSEC */
#endif /* __IPSEC_MANAGER_HPP__ */
