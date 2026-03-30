#!/usr/bin/env python3
"""
Prepare PCAP media files for SIPp's play_pcap_audio:

1. Convert DLT_LINUX_SLL2 (link-type 276) to DLT_EN10MB (Ethernet).
2. Strip non-IP packets (ARP, etc.) that would cause SIPp to abort with
   "Unsupported ethernet type" when they appear as the first frame.

DLT_LINUX_SLL2 header layout (20 bytes):
  protocol      2 bytes  (EtherType, big-endian)
  reserved      2 bytes
  if_index      4 bytes
  hatype        2 bytes
  pkttype       1 byte
  halen         1 byte
  haddr         8 bytes

Replacement Ethernet header (14 bytes):
  dst_mac       6 bytes (zeroed)
  src_mac       6 bytes (zeroed)
  ethertype     2 bytes (from SLL2 protocol field)

Usage:
  python3 convert_pcap_linktype.py file.pcap ...
  (overwrites files in-place; originals are renamed to .bak)
"""
import struct
import sys
from pathlib import Path

PCAP_GLOBAL_HDR_SIZE = 24
PCAP_PKT_HDR_SIZE = 16
SLL2_HDR_SIZE = 20
ETH_HDR_SIZE = 14
FAKE_MAC = b'\x00' * 6

DLT_LINUX_SLL2 = 276
DLT_EN10MB = 1
DLT_RAW = 12

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD


def _convert_sll2(src: bytes) -> bytes:
    """Convert DLT_LINUX_SLL2 to DLT_EN10MB, returning *src* unchanged if
    the link type is already Ethernet (or anything else)."""
    if len(src) < PCAP_GLOBAL_HDR_SIZE:
        raise ValueError("File too short to be a PCAP")

    magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, link_type = \
        struct.unpack_from('<IHHiIII', src, 0)

    if link_type != DLT_LINUX_SLL2:
        return src

    out = bytearray()
    out += struct.pack('<IHHiIII', magic, ver_maj, ver_min, thiszone,
                       sigfigs, snaplen, DLT_EN10MB)

    pos = PCAP_GLOBAL_HDR_SIZE
    while pos < len(src):
        if pos + PCAP_PKT_HDR_SIZE > len(src):
            break

        ts_sec, ts_usec, incl_len, orig_len = \
            struct.unpack_from('<IIII', src, pos)
        pos += PCAP_PKT_HDR_SIZE

        pkt = src[pos: pos + incl_len]
        pos += incl_len

        if len(pkt) < SLL2_HDR_SIZE:
            continue

        ethertype = pkt[0:2]
        ip_payload = pkt[SLL2_HDR_SIZE:]

        eth_hdr = FAKE_MAC + FAKE_MAC + ethertype
        new_pkt = eth_hdr + ip_payload

        delta = len(new_pkt) - len(pkt)
        out += struct.pack('<IIII',
                           ts_sec, ts_usec,
                           incl_len + delta,
                           orig_len + delta)
        out += new_pkt

    return bytes(out)


def _strip_non_ip(src: bytes) -> tuple[bytes, int]:
    """Remove non-IP packets from a DLT_EN10MB PCAP.

    SIPp's prepare_pkts() determines the EtherType offset from the first
    packet; if that packet is ARP (0x0806) the fatal ERROR() macro fires
    and SIPp aborts.  Even when ARP is not first, non-IP frames are
    useless for RTP playback, so we drop them all.

    Returns (output_bytes, number_of_dropped_packets).
    For DLT_RAW PCAPs (no Ethernet header) there is nothing to filter.
    """
    if len(src) < PCAP_GLOBAL_HDR_SIZE:
        raise ValueError("File too short to be a PCAP")

    magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, link_type = \
        struct.unpack_from('<IHHiIII', src, 0)

    if link_type != DLT_EN10MB:
        return src, 0

    out = bytearray(src[:PCAP_GLOBAL_HDR_SIZE])
    dropped = 0

    pos = PCAP_GLOBAL_HDR_SIZE
    while pos < len(src):
        if pos + PCAP_PKT_HDR_SIZE > len(src):
            break

        hdr_start = pos
        ts_sec, ts_usec, incl_len, orig_len = \
            struct.unpack_from('<IIII', src, pos)
        pos += PCAP_PKT_HDR_SIZE

        pkt = src[pos: pos + incl_len]
        pos += incl_len

        if len(pkt) < ETH_HDR_SIZE:
            dropped += 1
            continue

        ethertype = struct.unpack_from('>H', pkt, 12)[0]
        if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            dropped += 1
            continue

        out += src[hdr_start: pos]

    return bytes(out), dropped


def main():
    paths = [Path(p) for p in sys.argv[1:]] if len(sys.argv) > 1 else \
            list(Path('.').glob('*.pcap'))

    for path in paths:
        if not path.exists():
            print(f"skip (not found): {path}")
            continue

        data = path.read_bytes()
        converted = _convert_sll2(data)
        did_convert = converted is not data

        cleaned, n_dropped = _strip_non_ip(converted)
        did_strip = n_dropped > 0

        if not did_convert and not did_strip:
            print(f"skip (no changes needed): {path}")
            continue

        bak = path.with_suffix('.pcap.bak')
        path.rename(bak)
        path.write_bytes(cleaned)

        actions = []
        if did_convert:
            actions.append("SLL2→Ethernet")
        if did_strip:
            actions.append(f"stripped {n_dropped} non-IP packet(s)")
        print(f"{path}: {', '.join(actions)}  (original -> {bak})")


if __name__ == '__main__':
    main()
