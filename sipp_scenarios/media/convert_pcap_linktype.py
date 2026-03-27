#!/usr/bin/env python3
"""
Convert PCAP files with DLT_LINUX_SLL2 (link-type 276) to DLT_EN10MB
(Ethernet, link-type 1) so that SIPp's play_pcap_audio can read them.

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


def _convert(src: bytes) -> bytes:
    if len(src) < PCAP_GLOBAL_HDR_SIZE:
        raise ValueError("File too short to be a PCAP")

    # Parse global header
    magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, link_type = \
        struct.unpack_from('<IHHiIII', src, 0)

    if link_type != DLT_LINUX_SLL2:
        return src  # nothing to do

    out = bytearray()

    # Rewrite global header with DLT_EN10MB
    out += struct.pack('<IHHiIII', magic, ver_maj, ver_min, thiszone,
                       sigfigs, snaplen, DLT_EN10MB)

    pos = PCAP_GLOBAL_HDR_SIZE
    while pos < len(src):
        if pos + PCAP_PKT_HDR_SIZE > len(src):
            break  # truncated

        ts_sec, ts_usec, incl_len, orig_len = \
            struct.unpack_from('<IIII', src, pos)
        pos += PCAP_PKT_HDR_SIZE

        pkt = src[pos: pos + incl_len]
        pos += incl_len

        if len(pkt) < SLL2_HDR_SIZE:
            continue  # skip malformed packet

        ethertype = pkt[0:2]          # SLL2 protocol field (big-endian)
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


def main():
    paths = [Path(p) for p in sys.argv[1:]] if len(sys.argv) > 1 else \
            list(Path('.').glob('*.pcap'))

    for path in paths:
        if not path.exists():
            print(f"skip (not found): {path}")
            continue
        data = path.read_bytes()
        converted = _convert(data)
        if converted is data:
            print(f"skip (already DLT_EN10MB): {path}")
            continue
        bak = path.with_suffix('.pcap.bak')
        path.rename(bak)
        path.write_bytes(converted)
        print(f"converted: {path}  (original -> {bak})")


if __name__ == '__main__':
    main()
