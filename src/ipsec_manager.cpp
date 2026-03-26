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
 */

#ifdef USE_IPSEC

#include "sipp.hpp"
#include "ipsec_manager.hpp"
#include "xfrm_netlink.hpp"

#include <cstring>
#include <cstdlib>
#include <ctime>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/xfrm.h>
#include <unistd.h>

/* Global IPSec configuration is defined in sipp.hpp via MAYBE_EXTERN */

static bool spi_seeded = false;

IPSecManager::IPSecManager() : initialized_(false) {}

IPSecManager::~IPSecManager()
{
    if (initialized_) {
        xfrm_cleanup();
    }
}

int IPSecManager::init()
{
    if (initialized_)
        return 0;

    int ret = xfrm_init();
    if (ret == 0)
        initialized_ = true;
    return ret;
}

uint32_t IPSecManager::generate_spi()
{
    if (!spi_seeded) {
        srand(time(nullptr) ^ getpid());
        spi_seeded = true;
    }
    /* SPI must be > 255 per RFC 4303 */
    return (uint32_t)(rand() % 0xFFFF0000) + 256;
}

static uint16_t generate_ephemeral_port()
{
    if (!spi_seeded) {
        srand(time(nullptr) ^ getpid());
        spi_seeded = true;
    }
    uint16_t range = IPSEC_EPHEMERAL_PORT_MAX - IPSEC_EPHEMERAL_PORT_MIN + 1;
    return (uint16_t)(IPSEC_EPHEMERAL_PORT_MIN + (rand() % range));
}

int IPSecManager::allocate_local_params(IPSecParams &params, uint16_t port_c, uint16_t port_s)
{
    memset(&params, 0, sizeof(params));

    params.spi_uc = generate_spi();
    params.spi_us = generate_spi();

    /* Ensure SPIs are distinct */
    while (params.spi_us == params.spi_uc)
        params.spi_us = generate_spi();

    if (port_c != 0) {
        params.port_uc = port_c;
    } else {
        params.port_uc = generate_ephemeral_port();
    }

    if (port_s != 0) {
        params.port_us = port_s;
    } else {
        params.port_us = generate_ephemeral_port();
        while (params.port_us == params.port_uc)
            params.port_us = generate_ephemeral_port();
    }

    /* Set default algorithms */
    strncpy(params.algos.aalg, ipsec_aalg, sizeof(params.algos.aalg) - 1);
    strncpy(params.algos.ealg, ipsec_ealg, sizeof(params.algos.ealg) - 1);

    params.state = IPSEC_STATE_PARAMS_ALLOCATED;
    return 0;
}

void IPSecManager::set_keys(IPSecParams &params, const unsigned char *ck, const unsigned char *ik)
{
    memcpy(params.ck, ck, 16);
    memcpy(params.ik, ik, 16);
}

const char *IPSecManager::aalg_to_xfrm(const char *aalg_3gpp)
{
    if (!aalg_3gpp)
        return XFRM_AALG_HMAC_SHA1;
    if (strcasecmp(aalg_3gpp, "hmac-sha-1-96") == 0)
        return XFRM_AALG_HMAC_SHA1;
    if (strcasecmp(aalg_3gpp, "hmac-md5-96") == 0)
        return XFRM_AALG_HMAC_MD5;
    return XFRM_AALG_HMAC_SHA1;
}

const char *IPSecManager::ealg_to_xfrm(const char *ealg_3gpp)
{
    if (!ealg_3gpp)
        return XFRM_EALG_NULL;
    if (strcasecmp(ealg_3gpp, "aes-cbc") == 0)
        return XFRM_EALG_AES_CBC;
    if (strcasecmp(ealg_3gpp, "des-ede3-cbc") == 0)
        return XFRM_EALG_DES3;
    if (strcasecmp(ealg_3gpp, "null") == 0)
        return XFRM_EALG_NULL;
    return XFRM_EALG_NULL;
}

int IPSecManager::aalg_key_bits(const char *aalg_3gpp)
{
    if (!aalg_3gpp)
        return XFRM_AALG_SHA1_KEY_BITS;
    if (strcasecmp(aalg_3gpp, "hmac-sha-1-96") == 0)
        return XFRM_AALG_SHA1_KEY_BITS;
    if (strcasecmp(aalg_3gpp, "hmac-md5-96") == 0)
        return 128;
    return XFRM_AALG_SHA1_KEY_BITS;
}

int IPSecManager::ealg_key_bits(const char *ealg_3gpp)
{
    if (!ealg_3gpp)
        return XFRM_EALG_NULL_KEY_BITS;
    if (strcasecmp(ealg_3gpp, "aes-cbc") == 0)
        return XFRM_EALG_AES128_KEY_BITS;
    if (strcasecmp(ealg_3gpp, "des-ede3-cbc") == 0)
        return XFRM_EALG_DES3_KEY_BITS;
    if (strcasecmp(ealg_3gpp, "null") == 0)
        return XFRM_EALG_NULL_KEY_BITS;
    return XFRM_EALG_NULL_KEY_BITS;
}

int IPSecManager::setup_sa_pair(const IPSecParams &params,
                                const char *src, const char *dst,
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t spi)
{
    const char *xfrm_aalg = aalg_to_xfrm(params.algos.aalg);
    const char *xfrm_ealg = ealg_to_xfrm(params.algos.ealg);
    int aalg_bits = aalg_key_bits(params.algos.aalg);
    int ealg_bits = ealg_key_bits(params.algos.ealg);

    /*
     * For HMAC-SHA1-96, the kernel expects a 160-bit (20-byte) key.
     * IK from AKA is 128 bits (16 bytes). We zero-pad to 20 bytes.
     */
    unsigned char aalg_key[XFRM_IK_PADDED_LEN];
    memset(aalg_key, 0, sizeof(aalg_key));
    memcpy(aalg_key, params.ik, 16);

    const unsigned char *ealg_key_ptr = nullptr;
    if (ealg_bits > 0)
        ealg_key_ptr = params.ck;

    return xfrm_add_sa(src, dst, spi, src_port, dst_port, params.proto,
                       xfrm_aalg, aalg_key, aalg_bits,
                       xfrm_ealg, ealg_key_ptr, ealg_bits);
}

int IPSecManager::setup_policy_pair(const IPSecParams &params,
                                    const char *src, const char *dst,
                                    uint16_t src_port, uint16_t dst_port,
                                    uint32_t spi, int dir)
{
    return xfrm_add_policy(src, dst, src_port, dst_port, params.proto,
                           dir, spi, src, dst);
}

int IPSecManager::setup_security_associations(IPSecParams &params)
{
    if (!initialized_) {
        WARNING("IPSecManager not initialized");
        return -1;
    }

    if (params.state < IPSEC_STATE_PARAMS_ALLOCATED) {
        WARNING("IPSec params not allocated");
        return -1;
    }

    const char *local = params.local_ip;
    const char *remote = params.remote_ip;

    LOG_MSG("Setting up IPSec SAs: local=%s ports=%d/%d, remote=%s ports=%d/%d\n",
            local, params.port_uc, params.port_us,
            remote, params.port_pc, params.port_ps);

    /*
     * SA 1: UE:port_uc -> P-CSCF:port_ps  (outbound client to server)
     * The P-CSCF allocated spi_ps for traffic arriving at its server port.
     */
    if (setup_sa_pair(params, local, remote, params.port_uc, params.port_ps, params.spi_ps) < 0) {
        WARNING("Failed to create SA: UE:port_uc -> P-CSCF:port_ps");
        return -1;
    }

    /* Policy for SA 1: outbound */
    if (setup_policy_pair(params, local, remote, params.port_uc, params.port_ps,
                          params.spi_ps, XFRM_POLICY_OUT) < 0) {
        WARNING("Failed to create policy: UE:port_uc -> P-CSCF:port_ps (out)");
        return -1;
    }

    /*
     * SA 2: P-CSCF:port_ps -> UE:port_uc  (inbound, responses from server)
     * The UE allocated spi_uc for traffic arriving at its client port.
     */
    if (setup_sa_pair(params, remote, local, params.port_ps, params.port_uc, params.spi_uc) < 0) {
        WARNING("Failed to create SA: P-CSCF:port_ps -> UE:port_uc");
        return -1;
    }

    /* Policy for SA 2: inbound */
    if (setup_policy_pair(params, remote, local, params.port_ps, params.port_uc,
                          params.spi_uc, XFRM_POLICY_IN) < 0) {
        WARNING("Failed to create policy: P-CSCF:port_ps -> UE:port_uc (in)");
        return -1;
    }

    /*
     * SA 3: P-CSCF:port_pc -> UE:port_us  (inbound requests from P-CSCF client)
     * The UE allocated spi_us for traffic arriving at its server port.
     */
    if (setup_sa_pair(params, remote, local, params.port_pc, params.port_us, params.spi_us) < 0) {
        WARNING("Failed to create SA: P-CSCF:port_pc -> UE:port_us");
        return -1;
    }

    /* Policy for SA 3: inbound */
    if (setup_policy_pair(params, remote, local, params.port_pc, params.port_us,
                          params.spi_us, XFRM_POLICY_IN) < 0) {
        WARNING("Failed to create policy: P-CSCF:port_pc -> UE:port_us (in)");
        return -1;
    }

    /*
     * SA 4: UE:port_us -> P-CSCF:port_pc  (outbound responses from UE server)
     * The P-CSCF allocated spi_pc for traffic arriving at its client port.
     */
    if (setup_sa_pair(params, local, remote, params.port_us, params.port_pc, params.spi_pc) < 0) {
        WARNING("Failed to create SA: UE:port_us -> P-CSCF:port_pc");
        return -1;
    }

    /* Policy for SA 4: outbound */
    if (setup_policy_pair(params, local, remote, params.port_us, params.port_pc,
                          params.spi_pc, XFRM_POLICY_OUT) < 0) {
        WARNING("Failed to create policy: UE:port_us -> P-CSCF:port_pc (out)");
        return -1;
    }

    params.state = IPSEC_STATE_SA_ESTABLISHED;
    LOG_MSG("IPSec SAs established successfully (4 SA pairs + 4 policies)\n");
    return 0;
}

int IPSecManager::teardown_security_associations(IPSecParams &params)
{
    if (!initialized_)
        return -1;

    if (params.state < IPSEC_STATE_SA_ESTABLISHED)
        return 0;

    const char *local = params.local_ip;
    const char *remote = params.remote_ip;
    int errors = 0;

    LOG_MSG("Tearing down IPSec SAs\n");

    /* Delete policies first, then SAs */
    errors += (xfrm_del_policy(local, remote, params.port_uc, params.port_ps, params.proto, XFRM_POLICY_OUT) < 0);
    errors += (xfrm_del_policy(remote, local, params.port_ps, params.port_uc, params.proto, XFRM_POLICY_IN) < 0);
    errors += (xfrm_del_policy(remote, local, params.port_pc, params.port_us, params.proto, XFRM_POLICY_IN) < 0);
    errors += (xfrm_del_policy(local, remote, params.port_us, params.port_pc, params.proto, XFRM_POLICY_OUT) < 0);

    errors += (xfrm_del_sa(local, remote, params.spi_ps, params.proto) < 0);
    errors += (xfrm_del_sa(remote, local, params.spi_uc, params.proto) < 0);
    errors += (xfrm_del_sa(remote, local, params.spi_us, params.proto) < 0);
    errors += (xfrm_del_sa(local, remote, params.spi_pc, params.proto) < 0);

    params.state = IPSEC_STATE_TORN_DOWN;

    if (errors > 0) {
        WARNING("Some IPSec SAs/policies could not be removed (%d errors)", errors);
        return -1;
    }

    LOG_MSG("IPSec SAs torn down successfully\n");
    return 0;
}

#endif /* USE_IPSEC */
