#!/usr/bin/env python3
"""Stand-in PGW for a loopback test of SIPp's S8 support (see README.md).

Deliberately independent of SIPp's own GTP code: requests are parsed with
scapy's GTPv2 dissector, answers are built by hand from TS 29.274 and
TS 29.281. It accepts a Create Session Request for the APN "ims" and
rejects every other APN (cause 93), hands out 10.99.0.<n> as UE address and
10.88.0.1 as P-CSCF, answers a SIP REGISTER that arrives inside GTP-U with a
200 OK through the tunnel, and answers Delete Session and Echo Requests.

Dedicated bearer procedures are driven by the test through an "X-Bearer"
header in the REGISTER, carried out after the 200 OK:
  create  Create Bearer Request (QCI 1; uplink filter: UDP to the P-CSCF's
          port 5060), sent twice with one sequence number as a retransmission
  update  Update Bearer Request replacing that filter by one for port 9
  delete  Delete Bearer Request for the dedicated bearer
Every REGISTER is logged with the bearer it arrived on, and answered on it.

Usage: standin_pgw.py <address to bind UDP 2123 and 2152 on>
"""
import socket, struct, sys, select
from scapy.all import IP, UDP, raw
from scapy.contrib.gtp_v2 import GTPHeader as GTPv2
MY_IP = sys.argv[1]; PCSCF = "10.88.0.1"
c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); c.bind((MY_IP, 2123))
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); u.bind((MY_IP, 2152))
sessions = {}          # our c-teid -> dict
by_ue = {}             # ue ip -> dict
next_id = [1]
def ie(t, inst, v): return struct.pack("!BHB", t, len(v), inst) + v
def hdr(mtype, teid, seq, ies):
    return struct.pack("!BBHI", 0x48, mtype, 8 + len(ies), teid) + struct.pack("!I", seq << 8) + ies
def fteid(iface, teid, ip): return struct.pack("!BI", 0x80 | iface, teid) + socket.inet_aton(ip)
def ie_list(pkt):
    """The IEs of a GTPv2 message as scapy parsed them (message layer -> IE_list)."""
    return list(pkt.payload.IE_list) if hasattr(pkt.payload, "IE_list") else []
def find(pkt, name):
    for i in ie_list(pkt):
        if type(i).__name__ == name: return i
    return None
def ies_of(pkt):
    return [type(i).__name__ for i in ie_list(pkt)]
def tlvs(b):
    """(type, instance, value) of each IE in b, parsed by hand."""
    out = []; off = 0
    while off + 4 <= len(b):
        t, l, inst = struct.unpack("!BHB", b[off:off + 4])
        out.append((t, inst & 15, b[off + 4:off + 4 + l])); off += 4 + l
    return out
pgw_seq = [0x100]
def bearer_request(sess, what, addr):
    """Send the bearer request the test asked for (TS 29.274 §7.2.3, §7.2.15, §7.2.9.2)."""
    pgw_seq[0] += 1; seq = pgw_seq[0]
    pcscf = socket.inet_aton(PCSCF) + b"\xff\xff\xff\xff"
    if what == "create":
        match = b"\x30\x11" + b"\x10" + pcscf + b"\x50" + struct.pack("!H", 5060)
        tft = bytes([0x22, 0x10, 0, len(match)]) + match + bytes([0x21, 1, len(match)]) + match
        sess["ded_teid"] = 0x3000 + (sess["c_teid"] & 0xfff)
        bctx = (ie(73, 0, b"\x00") + ie(84, 0, tft) + ie(87, 1, fteid(5, sess["ded_teid"], MY_IP))
                + ie(80, 0, bytes([0x7c, 1]) + bytes(20)))
        msg = hdr(95, sess["sgw_c_teid"], seq, ie(73, 0, b"\x05") + ie(93, 0, bctx))
        c.sendto(msg, addr); c.sendto(msg, addr)       # the second one is a retransmission
    elif what == "update":
        match = b"\x30\x11" + b"\x50" + struct.pack("!H", 9)
        tft = bytes([0x81, 0x21, 1, len(match)]) + match
        bctx = ie(73, 0, bytes([sess.get("ebi", 0)])) + ie(84, 0, tft)
        c.sendto(hdr(97, sess["sgw_c_teid"], seq, ie(93, 0, bctx)), addr)
    elif what == "delete":
        c.sendto(hdr(99, sess["sgw_c_teid"], seq, ie(73, 1, bytes([sess.get("ebi", 0)]))), addr)
    print("%s Bearer Request imsi=%s seq=%d" % (what, sess["imsi"], seq), flush=True)
print("stand-in PGW on", MY_IP, flush=True)
while True:
    r, _, _ = select.select([c, u], [], [], 1)
    for s in r:
        data, addr = s.recvfrom(65535)
        if s is c:
            p = GTPv2(data)
            seq = p.seq; mtype = p.gtp_type
            if mtype == 1:      # Echo Request
                c.sendto(struct.pack("!BBH", 0x40, 2, 4 + 5) + struct.pack("!I", seq << 8) + ie(3, 0, b"\x01"), addr); continue
            if mtype == 32:     # Create Session Request
                names = ies_of(p)
                imsi = find(p, "IE_IMSI").IMSI.decode() if find(p, "IE_IMSI") else "?"
                ft = find(p, "IE_FTEID")
                bc = find(p, "IE_BearerContext")
                sgw_c_teid = ft.GRE_Key; sgw_c_ip = ft.ipv4
                sgw_u = None
                for sub in bc.IE_list:
                    if type(sub).__name__ == "IE_FTEID": sgw_u = sub
                print("CSR imsi=%s seq=%d teid=%d IEs=%s" % (imsi, seq, p.teid, ",".join(names)), flush=True)
                print("  sender F-TEID iface=%d teid=0x%x ip=%s | bearer F-TEID iface=%d teid=0x%x ip=%s | malformed=%s" % (
                    ft.InterfaceType, sgw_c_teid, sgw_c_ip, sgw_u.InterfaceType, sgw_u.GRE_Key, sgw_u.ipv4, any(n in ("Raw", "IE_NotImplementedTLV") for n in names)), flush=True)
                # What an MME takes from the HSS's subscription data, parsed by hand
                top = tlvs(data[12:])
                msisdn = "".join("%x%x" % (b & 15, b >> 4) for t, i, v in top if t == 76 for b in v).rstrip("f")
                ambr = [struct.unpack("!II", v[:8]) for t, i, v in top if t == 72]
                qos = [v2 for t, i, v in top if t == 93 for t2, i2, v2 in tlvs(v) if t2 == 80]
                print("  subscription: msisdn=%s ambr_ul=%s ambr_dl=%s qci=%s arp=%s" % (
                    msisdn or "-", ambr[0][0] if ambr else "-", ambr[0][1] if ambr else "-",
                    qos[0][1] if qos else "-", (qos[0][0] >> 2) & 15 if qos else "-"), flush=True)
                apn = find(p, "IE_APN").APN.decode()
                # Exact match, as a real PGW does it: a stray byte in the APN
                # (e.g. a trailing CR) must be rejected, not accepted.
                if apn != "ims":
                    c.sendto(hdr(33, sgw_c_teid, seq, ie(2, 0, b"\x5d\x00")), addr)     # 93 APN access denied
                    print("  -> rejected, cause 93 (apn %r)" % apn, flush=True); continue
                n = next_id[0]; next_id[0] += 1
                ue_ip = "10.99.0.%d" % n
                sess = dict(c_teid=0x1000 + n, u_teid=0x2000 + n, sgw_c_teid=sgw_c_teid, sgw_u_teid=sgw_u.GRE_Key,
                            sgw_ip=sgw_u.ipv4, ue_ip=ue_ip, imsi=imsi)
                sessions[sess["c_teid"]] = sess; by_ue[ue_ip] = sess
                pco = b"\x80" + struct.pack("!HB", 0x000d, 4) + socket.inet_aton("8.8.8.8") + struct.pack("!HB", 0x000c, 4) + socket.inet_aton(PCSCF)
                bctx = ie(73, 0, b"\x05") + ie(2, 0, b"\x10\x00") + ie(87, 2, fteid(5, sess["u_teid"], MY_IP))
                ies = (ie(2, 0, b"\x10\x00") + ie(87, 1, fteid(7, sess["c_teid"], MY_IP)) + ie(79, 0, b"\x01" + socket.inet_aton(ue_ip))
                       + ie(78, 0, pco) + ie(93, 0, bctx) + ie(3, 0, b"\x01"))
                c.sendto(hdr(33, sgw_c_teid, seq, ies), addr)
                print("  -> accepted, UE %s" % ue_ip, flush=True)
            elif mtype == 36:   # Delete Session Request
                sess = sessions.pop(p.teid, None)
                print("DSR teid=0x%x known=%s IEs=%s" % (p.teid, sess is not None, ",".join(ies_of(p))), flush=True)
                if sess:
                    by_ue.pop(sess["ue_ip"], None)
                    c.sendto(hdr(37, sess["sgw_c_teid"], seq, ie(2, 0, b"\x10\x00")), addr)
            elif mtype in (96, 98, 100):    # Create / Update / Delete Bearer Response
                sess = sessions.get(p.teid)
                name = {96: "CBRsp", 98: "UBRsp", 100: "DBRsp"}[mtype]
                top = tlvs(data[12:])
                cause = [v[0] for t, i, v in top if t == 2]
                ctx = [tlvs(v) for t, i, v in top if t == 93]
                b = ctx[0] if ctx else []
                ebi = [v[0] for t, i, v in b if t == 73]
                bcause = [v[0] for t, i, v in b if t == 2]
                line = "%s known=%s cause=%s bearer_cause=%s ebi=%s" % (name, sess is not None, cause, bcause, ebi)
                if mtype == 96 and sess:
                    sgw = [v for t, i, v in b if t == 87 and i == 2]
                    echo = [v for t, i, v in b if t == 87 and i == 3]
                    sgw_teid = struct.unpack("!I", sgw[0][1:5])[0] if sgw else 0
                    line += " sgw_iface=%s sgw_u_teid=0x%x pgw_fteid_echo=%s" % (
                        sgw[0][0] & 0x3f if sgw else None, sgw_teid,
                        "ok" if echo and echo[0] == fteid(5, sess["ded_teid"], MY_IP) else "WRONG")
                    if "sgw_ded_teid" in sess:
                        line += " retransmission=%s" % ("same answer" if (sgw_teid, ebi[0]) == (sess["sgw_ded_teid"], sess["ebi"]) else "DIFFERENT ANSWER")
                    elif cause == [16] and ebi:
                        sess["sgw_ded_teid"] = sgw_teid; sess["ebi"] = ebi[0]; sess["ded_active"] = True
                if mtype == 100 and sess and cause == [16]:
                    sess["ded_active"] = False
                print(line, flush=True)
        else:
            flags, mtype, length, teid = struct.unpack("!BBHI", data[:8])
            if mtype != 255: continue
            inner = IP(data[8 + (4 if flags & 7 else 0):])
            sess = by_ue.get(inner.src)
            ok = sess is not None and sess["u_teid"] == teid
            dedicated = sess is not None and sess.get("ded_active") and sess.get("ded_teid") == teid
            if UDP in inner and bytes(inner[UDP].payload).startswith(b"REGISTER"):
                req = bytes(inner[UDP].payload).decode()
                print("GTP-U uplink teid=0x%x (%s) %s:%d > %s:%d REGISTER, %d bytes" % (
                    teid, "matches session" if ok else "matches dedicated bearer" if dedicated else "UNKNOWN", inner.src, inner[UDP].sport, inner.dst, inner[UDP].dport, len(req)), flush=True)
                if not ok and not dedicated: continue
                keep = [l for l in req.split("\r\n") if l.split(":")[0] in ("Via", "From", "To", "Call-ID", "CSeq", "X-Info")]
                rsp = "SIP/2.0 200 OK\r\n" + "\r\n".join(keep) + "\r\nContent-Length: 0\r\n\r\n"
                print("  " + [l for l in keep if l.startswith("X-Info")][0], flush=True)
                back = IP(src=inner.dst, dst=inner.src) / UDP(sport=inner[UDP].dport, dport=inner[UDP].sport) / rsp.encode()
                b = raw(back)
                u.sendto(struct.pack("!BBHI", 0x30, 255, len(b), sess["sgw_ded_teid"] if dedicated else sess["sgw_u_teid"]) + b, (sess["sgw_ip"], 2152))
                step = [l.split(":", 1)[1].strip() for l in req.split("\r\n") if l.startswith("X-Bearer:")]
                if step:
                    cseq = [l for l in keep if l.startswith("CSeq")][0]
                    print("BEARER TEST imsi=%s %s arrived on the %s bearer" % (sess["imsi"], cseq, "dedicated" if dedicated else "default"), flush=True)
                    if step[0] in ("create", "update", "delete"):
                        bearer_request(sess, step[0], (sess["sgw_ip"], 2123))
