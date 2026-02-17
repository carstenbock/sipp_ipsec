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
 *  SIP Security headers per RFC 3329 and 3GPP TS 33.203.
 *  Handles Security-Client, Security-Server, and Security-Verify headers
 *  for the ipsec-3gpp security mechanism.
 */

#ifndef __SECURITY_HEADERS_HPP__
#define __SECURITY_HEADERS_HPP__

#ifdef USE_IPSEC

#include "ipsec_manager.hpp"

/**
 * Build a Security-Client header value for the initial REGISTER.
 *
 * Format per 3GPP TS 33.203:
 *   ipsec-3gpp; alg=hmac-sha-1-96; ealg=aes-cbc;
 *     spi-c=<spi_uc>; spi-s=<spi_us>;
 *     port-c=<port_uc>; port-s=<port_us>
 *
 * @param params   IPSecParams with local SPIs and ports allocated
 * @param result   Output buffer
 * @param result_len  Size of output buffer
 * @return Number of bytes written, or 0 on error
 */
int build_security_client_header(const IPSecParams &params,
                                 char *result, size_t result_len);

/**
 * Parse a Security-Server header received from the P-CSCF in the 401 response.
 * Extracts: spi-c, spi-s, port-c, port-s, alg, ealg
 *
 * @param header   The raw Security-Server header value
 * @param params   Output: fills spi_pc, spi_ps, port_pc, port_ps and algos
 * @return 0 on success, -1 on parse error
 */
int parse_security_server_header(const char *header, IPSecParams &params);

/**
 * Build a Security-Verify header value for the second REGISTER.
 * This is an exact echo of the Security-Server header received in the 401.
 *
 * @param security_server_value  The raw Security-Server value from 401
 * @param result   Output buffer
 * @param result_len  Size of output buffer
 * @return Number of bytes written, or 0 on error
 */
int build_security_verify_header(const char *security_server_value,
                                 char *result, size_t result_len);

#endif /* USE_IPSEC */
#endif /* __SECURITY_HEADERS_HPP__ */
