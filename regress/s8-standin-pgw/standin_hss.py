#!/usr/bin/env python3
"""Stand-in HSS for a loopback test of SIPp's S6a support (see README.md).

Independent of SIPp's Diameter code: messages are parsed and built by hand
from RFC 6733 and TS 29.272. It answers the capabilities exchange, AIR, ULR
and PUR, and behaves by the last three digits of the IMSI:
  404  AIR answered with DIAMETER_ERROR_USER_UNKNOWN (5001, experimental)
  504  ULR answered with DIAMETER_ERROR_ROAMING_NOT_ALLOWED (5004, experimental)
  317  a Cancel-Location-Request follows the Update Location one second later
Every successful ULR is followed by an Insert-Subscriber-Data-Request, and
each connection gets one Device-Watchdog-Request, so SIPp's answers to the
requests of an HSS are exercised too.

Usage: standin_hss.py <address> <tcp|sctp>
"""
import select, socket, struct, sys, time

MY_IP, PROTO = sys.argv[1], sys.argv[2]
HOST, REALM = b"hss.epc.mnc024.mcc262.3gppnetwork.org", b"epc.mnc024.mcc262.3gppnetwork.org"
TGPP, S6A = 10415, 16777251

def avp(code, data, vendor=0, mandatory=True):
    flags = (0x80 if vendor else 0) | (0x40 if mandatory else 0)
    hdr = struct.pack("!IB", code, flags) + (len(data) + (12 if vendor else 8)).to_bytes(3, "big")
    if vendor: hdr += struct.pack("!I", vendor)
    return hdr + data + b"\0" * (-len(data) % 4)
def u32(code, v, vendor=0): return avp(code, struct.pack("!I", v), vendor)
def msg(cmd, app, flags, hbh, e2e, avps):
    return b"\x01" + (20 + len(avps)).to_bytes(3, "big") + bytes([flags]) + cmd.to_bytes(3, "big") + struct.pack("!III", app, hbh, e2e) + avps
def avps_of(b):
    """{(code, vendor): [data, ...]}"""
    out = {}; off = 0
    while off + 8 <= len(b):
        code, flags = struct.unpack("!IB", b[off:off + 5]); ln = int.from_bytes(b[off + 5:off + 8], "big")
        hdr = 12 if flags & 0x80 else 8
        vendor = struct.unpack("!I", b[off + 8:off + 12])[0] if flags & 0x80 else 0
        out.setdefault((code, vendor), []).append(b[off + hdr:off + ln]); off += (ln + 3) & ~3
    return out
def first(a, code, vendor=0, default=b""): return a.get((code, vendor), [default])[0]
def tbcd(digits):
    d = digits + ("f" if len(digits) % 2 else "")
    return bytes(int(d[i + 1] + d[i], 16) for i in range(0, len(d), 2))
def origin(): return avp(264, HOST) + avp(296, REALM)
def vsa(): return avp(260, u32(266, TGPP) + u32(258, S6A))
def experimental(code): return avp(297, u32(266, TGPP) + u32(298, code))
def subscription(imsi):
    def apn(ctx, name, pdn, qci, prio, ul, dl):
        return avp(1430, u32(1423, ctx, TGPP) + u32(1456, pdn, TGPP) + avp(493, name)
                   + avp(1431, u32(1028, qci, TGPP) + avp(1034, u32(1046, prio, TGPP) + u32(1047, 1, TGPP) + u32(1048, 0, TGPP), TGPP), TGPP)
                   + avp(1435, u32(516, ul, TGPP) + u32(515, dl, TGPP), TGPP), TGPP)
    return avp(1400, avp(701, tbcd("49155500000" + imsi[-2:]), TGPP) + u32(1424, 0, TGPP)
               + avp(1435, u32(516, 50000000, TGPP) + u32(515, 100000000, TGPP), TGPP)
               + avp(1429, u32(1423, 1, TGPP) + u32(1428, 0, TGPP)
                     + apn(1, b"internet", 2, 9, 8, 50000000, 100000000)
                     + apn(2, b"ims", 0, 5, 3, 384000, 640000), TGPP), TGPP)

ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_SCTP if PROTO == "sctp" else socket.IPPROTO_TCP)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind((MY_IP, 3868)); ls.listen(8)
print("stand-in HSS on %s:3868/%s" % (MY_IP, PROTO), flush=True)
conns = {}          # socket -> dict(buf, peer)
later = []          # (time, socket, message, text)
seq = [0x5000]
def request(c, cmd, name, imsi, extra, delay=0.0):
    seq[0] += 1
    sid = b"hss;%d;%d" % (int(time.time()), seq[0])
    m = msg(cmd, S6A, 0xc0, seq[0], seq[0], avp(263, sid) + vsa() + u32(277, 1) + origin()
            + avp(293, conns[c]["peer"]) + avp(283, conns[c]["realm"]) + avp(1, imsi.encode()) + extra)
    later.append((time.time() + delay, c, m, "%s sent imsi=%s hbh=%d" % (name, imsi, seq[0])))

while True:
    now = time.time()
    for item in [x for x in later if x[0] <= now]:
        later.remove(item)
        if item[1] in conns:
            try: item[1].send(item[2]); print(item[3], flush=True)
            except OSError: pass
    r, _, _ = select.select([ls] + list(conns), [], [], 0.01)
    for s in r:
        if s is ls:
            c, addr = ls.accept(); conns[c] = dict(buf=b"", peer=b"", realm=b""); continue
        try: data = s.recv(65535)
        except OSError: data = b""
        if not data:
            print("connection closed by %s" % conns[s]["peer"].decode(), flush=True); del conns[s]; s.close(); continue
        conns[s]["buf"] += data
        while len(conns[s]["buf"]) >= 20 and len(conns[s]["buf"]) >= int.from_bytes(conns[s]["buf"][1:4], "big"):
            ln = int.from_bytes(conns[s]["buf"][1:4], "big")
            m, conns[s]["buf"] = conns[s]["buf"][:ln], conns[s]["buf"][ln:]
            flags = m[4]; cmd = int.from_bytes(m[5:8], "big"); app, hbh, e2e = struct.unpack("!III", m[8:20])
            a = avps_of(m[20:])
            if not flags & 0x80:        # an answer to one of our requests
                rc = struct.unpack("!I", first(a, 268, default=b"\0\0\0\0"))[0]
                name = {280: "DWA", 317: "CLA", 319: "IDA", 282: "DPA"}.get(cmd, "answer %d" % cmd)
                print("%s received result=%d hbh=%d session_id=%s origin=%s" % (
                    name, rc, hbh, "yes" if (263, 0) in a else "no", first(a, 264).decode()), flush=True)
                continue
            ans = lambda avps, f=0x40: s.send(msg(cmd, app, f if flags & 0x40 else 0, hbh, e2e, avps))
            imsi = first(a, 1).decode()
            sid = avp(263, first(a, 263))
            if cmd == 257:              # CER
                conns[s]["peer"], conns[s]["realm"] = first(a, 264), first(a, 296)
                apps = [struct.unpack("!I", first(avps_of(v), 258))[0] for v in a.get((260, 0), [])]
                print("CER origin_host=%s origin_realm=%s host_ip=%s s6a_advertised=%s" % (
                    first(a, 264).decode(), first(a, 296).decode(), socket.inet_ntoa(first(a, 257)[2:6]), S6A in apps), flush=True)
                s.send(msg(257, 0, 0, hbh, e2e, u32(268, 2001) + origin() + avp(257, b"\0\x01" + socket.inet_aton(MY_IP))
                           + u32(266, 0) + avp(269, b"standin-hss", mandatory=False) + u32(265, TGPP) + vsa()))
                seq[0] += 1
                later.append((time.time(), s, msg(280, 0, 0x80, seq[0], seq[0], origin()), "DWR sent hbh=%d" % seq[0]))
            elif cmd == 280:            # DWR
                s.send(msg(280, 0, 0, hbh, e2e, u32(268, 2001) + origin()))
            elif cmd == 282:            # DPR
                print("DPR from %s" % first(a, 264).decode(), flush=True)
                try: s.send(msg(282, 0, 0, hbh, e2e, u32(268, 2001) + origin()))
                except OSError: pass
            elif cmd in (318, 316, 321):
                name = {318: "AIR", 316: "ULR", 321: "PUR"}[cmd]
                plmn = first(a, 1407, TGPP).hex()
                ulr_flags = struct.unpack("!I", first(a, 1405, TGPP, b"\0\0\0\0"))[0]
                rat = struct.unpack("!I", first(a, 1032, TGPP, b"\0\0\0\0"))[0]
                ti = avps_of(first(a, 1401, TGPP))
                print("%s imsi=%s session_id=%s origin_host=%s dest_realm=%s visited_plmn=%s proxiable=%s%s" % (
                    name, imsi, first(a, 263).decode(), first(a, 264).decode(), first(a, 283).decode(), plmn or "-",
                    bool(flags & 0x40), " ulr_flags=0x%x rat=%d imei=%s sv=%s" % (
                        ulr_flags, rat, first(ti, 1402, TGPP).decode(), first(ti, 1403, TGPP).decode()) if cmd == 316 else ""), flush=True)
                head = sid + vsa() + u32(277, 1) + origin()
                if cmd == 318 and imsi.endswith("404"):
                    ans(head + experimental(5001)); print("  -> 5001 user unknown", flush=True)
                elif cmd == 318:
                    vec = avp(1414, avp(1447, bytes(16), TGPP) + avp(1448, bytes(8), TGPP) + avp(1449, bytes(16), TGPP) + avp(1450, bytes(32), TGPP), TGPP)
                    ans(head + u32(268, 2001) + avp(1413, vec, TGPP))
                elif cmd == 316 and imsi.endswith("504"):
                    ans(head + experimental(5004)); print("  -> 5004 roaming not allowed", flush=True)
                elif cmd == 316:
                    ans(head + u32(268, 2001) + u32(1406, 1, TGPP) + subscription(imsi))
                    request(s, 319, "IDR", imsi, avp(1400, u32(1424, 0, TGPP), TGPP))
                    if imsi.endswith("317"):
                        request(s, 317, "CLR", imsi, u32(1420, 2, TGPP), 1.0)
                else:
                    ans(head + u32(268, 2001) + u32(1442, 0, TGPP))
            else:
                s.send(msg(cmd, app, 0x20, hbh, e2e, u32(268, 3001) + origin()))
