#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Every media file of the scenarios holds one RTP stream and nothing else.

Why it matters: play_pcap_audio sends every UDP packet of the file, with the
ports shifted relative to the lowest destination port in it. A file with a
whole call (SIP, both RTP directions, RTCP) sent SIP and two streams' worth
of RTP from ports the SDP did not announce, so a dedicated bearer whose
packet filter names the SDP port matched none of it (KI-9). The payload type
must be the one the test-runner announces in its SDP for the file
(apps/test-runner/scenario_generator/codecs.py), and the timing must be that
of a live 20 ms stream, because SIPp replays the capture's own timing.
"""

import statistics
import struct
import unittest
from pathlib import Path

MEDIA = Path(__file__).resolve().parents[1] / "sipp_scenarios" / "media"

# file: (payload type, RTP clock ticks per 20 ms packet)
EXPECTED = {
    "amr-nb.pcap": (96, 160),
    "amr-wb.pcap": (98, 320),
    "evs-ue-side.pcap": (116, 320),
    "g722-gw-side.pcap": (9, 160),  # G.722 has an 8 kHz RTP clock (RFC 3551)
    "g722-ref.pcap": (9, 160),
    "pcma.pcap": (8, 160),
    "pcma_rtp.pcap": (8, 160),
    "pcmu.pcap": (0, 160),
}


def read_pcap(path):
    """(linktype, [(timestamp, frame)]) of a classic microsecond pcap."""
    data = path.read_bytes()
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise AssertionError(f"{path.name}: not a microsecond pcap")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    frames, off = [], 24
    while off < len(data):
        sec, usec, incl, orig = struct.unpack(endian + "IIII", data[off:off + 16])
        if incl != orig:
            raise AssertionError(f"{path.name}: truncated frame (SIPp refuses those)")
        frames.append((sec + usec / 1e6, data[off + 16:off + 16 + incl]))
        off += 16 + incl
    return linktype, frames


class MediaPcapTests(unittest.TestCase):
    def test_every_media_file_is_known(self):
        # A new file must be checked like the others.
        self.assertEqual(sorted(p.name for p in MEDIA.glob("*.pcap")), sorted(EXPECTED))

    def test_one_rtp_stream_per_file(self):
        for name, (want_pt, ticks) in EXPECTED.items():
            with self.subTest(file=name):
                linktype, frames = read_pcap(MEDIA / name)
                self.assertEqual(linktype, 1, "Ethernet")
                flows, ssrcs, pts, packets = set(), set(), set(), []
                for ts, frame in frames:
                    self.assertEqual(frame[12:14], b"\x08\x00", "IPv4 only")
                    ip = frame[14:]
                    ihl = (ip[0] & 0x0F) * 4
                    self.assertEqual(ip[9], 17, "UDP only")
                    udp = ip[ihl:ihl + struct.unpack("!H", ip[ihl + 4:ihl + 6])[0]]
                    sport, dport = struct.unpack("!HH", udp[:4])
                    flows.add((ip[12:16], sport, ip[16:20], dport))
                    rtp = udp[8:]
                    self.assertEqual(rtp[0] >> 6, 2, "RTP version 2")
                    pts.add(rtp[1] & 0x7F)
                    seq, rtp_ts, ssrc = struct.unpack("!HII", rtp[2:12])
                    ssrcs.add(ssrc)
                    packets.append((ts, seq, rtp_ts))

                self.assertEqual(len(flows), 1, "one direction: one address and port pair")
                self.assertEqual(len(ssrcs), 1, "one SSRC")
                self.assertEqual(pts, {want_pt}, "payload type of the SDP")
                pairs = list(zip(packets, packets[1:]))
                self.assertTrue(all((b[1] - a[1]) & 0xFFFF == 1 for a, b in pairs),
                                "sequence numbers without gaps")
                self.assertTrue(all((b[2] - a[2]) & 0xFFFFFFFF == ticks for a, b in pairs),
                                "RTP timestamps advance by one 20 ms frame")
                gaps = [b[0] - a[0] for a, b in pairs]
                self.assertTrue(0.018 <= statistics.median(gaps) <= 0.022,
                                f"median gap {statistics.median(gaps) * 1000:.1f} ms")
                self.assertLess(max(gaps), 0.060, "no pause in the stream")
                self.assertGreaterEqual(packets[-1][0] - packets[0][0], 5.0, "at least 5 s")


if __name__ == "__main__":
    unittest.main()
