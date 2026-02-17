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
 */

#ifndef __XFRM_NETLINK_HPP__
#define __XFRM_NETLINK_HPP__

#ifdef USE_IPSEC

#include <stdint.h>

/* Algorithm identifiers matching 3GPP TS 33.203 / Linux XFRM names */
#define XFRM_AALG_HMAC_SHA1  "hmac(sha1)"
#define XFRM_AALG_HMAC_MD5   "hmac(md5)"
#define XFRM_EALG_AES_CBC    "cbc(aes)"
#define XFRM_EALG_NULL       "ecb(cipher_null)"
#define XFRM_EALG_DES3       "cbc(des3_ede)"

/* Key sizes in bits */
#define XFRM_AALG_SHA1_KEY_BITS   160
#define XFRM_EALG_AES128_KEY_BITS 128
#define XFRM_EALG_NULL_KEY_BITS   0
#define XFRM_EALG_DES3_KEY_BITS   192

/* IK is 128 bits but HMAC-SHA1-96 expects 160-bit key; we zero-pad */
#define XFRM_IK_PADDED_LEN 20

/**
 * Add a Security Association (SA) to the kernel XFRM subsystem.
 *
 * @param src_ip     Source IP address (dotted string, IPv4 or IPv6)
 * @param dst_ip     Destination IP address
 * @param spi        SPI value (host byte order)
 * @param src_port   Source port for selector
 * @param dst_port   Destination port for selector
 * @param proto      Upper-layer protocol for selector (IPPROTO_UDP or IPPROTO_TCP)
 * @param aalg_name  Authentication algorithm name (e.g. XFRM_AALG_HMAC_SHA1)
 * @param aalg_key   Authentication key (IK, 16 bytes)
 * @param aalg_bits  Key length in bits
 * @param ealg_name  Encryption algorithm name (e.g. XFRM_EALG_AES_CBC, or NULL for auth-only)
 * @param ealg_key   Encryption key (CK, 16 bytes), or NULL
 * @param ealg_bits  Key length in bits
 * @return 0 on success, -1 on error
 */
int xfrm_add_sa(const char *src_ip, const char *dst_ip,
                uint32_t spi, uint16_t src_port, uint16_t dst_port,
                int proto,
                const char *aalg_name, const unsigned char *aalg_key, int aalg_bits,
                const char *ealg_name, const unsigned char *ealg_key, int ealg_bits);

/**
 * Delete a Security Association from the kernel.
 */
int xfrm_del_sa(const char *src_ip, const char *dst_ip,
                uint32_t spi, int proto);

/**
 * Add a Security Policy (SP) to the kernel XFRM subsystem.
 *
 * @param src_ip     Source address for selector
 * @param dst_ip     Destination address for selector
 * @param src_port   Source port for selector
 * @param dst_port   Destination port for selector
 * @param proto      Upper-layer protocol (IPPROTO_UDP or IPPROTO_TCP)
 * @param dir        Policy direction: 0=out, 1=in, 2=fwd
 * @param spi        SPI for the SA template
 * @param tmpl_src   Template source IP (tunnel endpoint)
 * @param tmpl_dst   Template destination IP (tunnel endpoint)
 * @return 0 on success, -1 on error
 */
int xfrm_add_policy(const char *src_ip, const char *dst_ip,
                    uint16_t src_port, uint16_t dst_port, int proto,
                    int dir, uint32_t spi,
                    const char *tmpl_src, const char *tmpl_dst);

/**
 * Delete a Security Policy from the kernel.
 */
int xfrm_del_policy(const char *src_ip, const char *dst_ip,
                    uint16_t src_port, uint16_t dst_port, int proto,
                    int dir);

/**
 * Initialize the XFRM netlink socket. Called once at startup.
 * @return 0 on success, -1 on error.
 */
int xfrm_init(void);

/**
 * Cleanup the XFRM netlink socket.
 */
void xfrm_cleanup(void);

#endif /* USE_IPSEC */
#endif /* __XFRM_NETLINK_HPP__ */
