# S8 and S6a loopback test with a stand-in PGW and HSS

Checks SIPp's S8 support (`docs/s8hr.rst`) end to end without a core network:
Create Session over GTPv2-C, the GTP-U user plane in both directions, Delete
Session, an expected rejection, an unexpected one, the T3/N3 timeout, and a
dedicated bearer: Create Bearer (also retransmitted), uplink on its TEID by
its packet filter, Update Bearer with a replaced filter, Delete Bearer, and
`<s8_wait_bearer>`. With the stand-in HSS (`standin_hss.py`, Diameter over
TCP) it also checks S6a: AIR, ULR and PUR, the HSS's subscription data
arriving in the Create Session Request, "user unknown" and "roaming not
allowed", SIPp's answers to the HSS's Insert Subscriber Data, Cancel Location
and watchdog requests, and `<s6a_wait_cancel>`.

The PGW is `standin_pgw.py`. It does not share code with SIPp: it parses
SIPp's requests with scapy's GTPv2 dissector and builds its answers by hand
from TS 29.274 / TS 29.281, so a mistake in SIPp's codec is not mirrored on
the other side. It is not a PGW: no PCC, no charging; a dedicated bearer
only when the test asks for one with an `X-Bearer` header.

## Run

    regress/s8-standin-pgw/run-in-docker.sh [sipp image]

The SIPp image defaults to `sipp-ipsec:s8`; build one from the repository
root with `docker build -t sipp-ipsec:s8 -f docker/Dockerfile.ipsec .`. The
script needs Docker and starts the SIPp container with `NET_ADMIN` and
`/dev/net/tun`. It is not part of `regress/runtests`, which runs
unprivileged.

Exit status 0 if every check passed.

## What it does not cover

Open5GS itself, IMS registration with AKA and IPsec through the bearer,
RTP, Diameter over SCTP, a DRA, and anything about reachability on a real network.
