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
 *  GTP-U user plane (3GPP TS 29.281) for the S8 emulation: SIPp as the
 *  S8 side of a visited SGW. UE IP packets travel between a TUN device,
 *  where SIPp's ordinary sockets live on the UEs' addresses, and GTP-U
 *  tunnels to the PGW-U.
 */

#ifndef __GTPU_HPP__
#define __GTPU_HPP__

#ifdef USE_S8

#include <stdint.h>
#include <stddef.h>
#include <vector>

/* --- Codec, exposed for the unit tests ---------------------------------- */

/* G-PDU: 8-byte header without optional fields (TS 29.281 §5.1) + T-PDU */
std::vector<uint8_t> gtpu_encode_gpdu(uint32_t teid, const uint8_t *pkt, size_t len);

/* Result of parsing a GTP-U message */
struct GtpuMsg {
    uint8_t type;           /* 1 Echo Request, 2 Echo Response, 26 Error
                               Indication, 254 End Marker, 255 G-PDU */
    uint32_t teid;
    uint16_t seq;           /* valid if has_seq */
    bool has_seq;
    const uint8_t *payload; /* T-PDU, or the IEs of a signalling message */
    size_t payload_len;
};
bool gtpu_decode(const uint8_t *msg, size_t len, GtpuMsg &out);

/* --- Data path ---------------------------------------------------------- */

/*
 * Create the TUN device, bind UDP 2152 on local_ip and start the forwarder
 * thread. Idempotent. Returns 0, or -1 with the reason in gtpu_error().
 * Needs CAP_NET_ADMIN and /dev/net/tun.
 */
int gtpu_start(const char *local_ip);
const char *gtpu_error();

/*
 * Bring a UE's default bearer into service: its address becomes a local
 * address (on the TUN device, routed there by source), uplink goes to
 * peer_ip with peer_teid, downlink arrives on local_teid.
 */
int gtpu_add_ue(const char *ue_ip, uint32_t local_teid,
                const char *peer_ip, uint32_t peer_teid);
void gtpu_del_ue(const char *ue_ip);

/*
 * One packet filter of a TFT, as far as it selects uplink packets
 * (TS 24.008 §10.5.6.12). "Local" is the UE, "remote" the other end.
 * Addresses are in network byte order; a component that was not given
 * matches everything.
 */
struct GtpuFilter {
    uint8_t precedence;         /* lower value is evaluated first */
    int protocol;               /* IP protocol, -1 for any */
    uint32_t local_addr, local_mask;
    uint32_t remote_addr, remote_mask;
    uint16_t local_port_lo, local_port_hi;
    uint16_t remote_port_lo, remote_port_hi;
    bool never;                 /* has a component an IPv4 packet cannot meet */

    GtpuFilter() : precedence(0), protocol(-1), local_addr(0), local_mask(0),
        remote_addr(0), remote_mask(0), local_port_lo(0), local_port_hi(65535),
        remote_port_lo(0), remote_port_hi(65535), never(false) {}
};

/* Does the uplink IPv4 packet pkt meet the filter? Exposed for the unit tests. */
bool gtpu_filter_matches(const GtpuFilter &f, const uint8_t *pkt, size_t len);

/*
 * Add a dedicated bearer to a UE, or replace the one with this EBI. Uplink
 * packets that meet one of its filters leave with peer_teid; the others stay
 * on the default bearer (TS 23.401 §4.7.2.1: the UE's uplink TFT decides).
 * Downlink is accepted on local_teid.
 */
int gtpu_add_bearer(const char *ue_ip, uint8_t ebi, uint32_t local_teid,
                    const char *peer_ip, uint32_t peer_teid,
                    const std::vector<GtpuFilter> &uplink);
/* New uplink filters for a bearer (Update Bearer). */
void gtpu_set_filters(const char *ue_ip, uint8_t ebi, const std::vector<GtpuFilter> &uplink);
void gtpu_del_bearer(const char *ue_ip, uint8_t ebi);
/* Packets a dedicated bearer has carried so far; false if there is none. */
bool gtpu_bearer_counters(const char *ue_ip, uint8_t ebi,
                          unsigned long &uplink, unsigned long &downlink);

/* Remove every UE and the device (process exit). */
void gtpu_stop();

/* A TEID for downlink that no other bearer of this process uses. */
uint32_t gtpu_new_teid();

#endif /* USE_S8 */
#endif /* __GTPU_HPP__ */
