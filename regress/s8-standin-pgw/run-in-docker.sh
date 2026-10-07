#!/bin/sh
# S8 loopback test against the stand-in PGW; see README.md.
set -u
cd "$(dirname "$0")"
SIPP_IMAGE="${1:-sipp-ipsec:s8}"
PGW=s8-regress-pgw
UE=s8-regress-sipp
OUT=$(mktemp -d)
failed=0

cleanup() {
    docker rm -f "$PGW" "$UE" >/dev/null 2>&1
    rm -rf "$OUT"
}
trap cleanup EXIT

check() {   # check <description> <expected> <actual>
    if [ "$2" = "$3" ]; then
        echo "ok   - $1"
    else
        echo "FAIL - $1 (expected '$2', got '$3')"
        failed=1
    fi
}

docker build -q -t s8-standin-pgw . >/dev/null || exit 2
docker rm -f "$PGW" "$UE" >/dev/null 2>&1

printf 'SEQUENTIAL\n' > "$OUT/users.csv"
i=1
while [ $i -le 10 ]; do
    printf '0010100000000%02d;+49155500000%02d;ims\n' $i $i >> "$OUT/users.csv"
    i=$((i + 1))
done
sed 's/expect="93"/expect="16"/' rejected.xml > "$OUT/rejected_unexpected.xml"
sed 's/OPTIONAL/false/' no_bearer.xml > "$OUT/no_bearer.xml"
sed 's/OPTIONAL/true/' no_bearer.xml > "$OUT/no_bearer_optional.xml"
cp session.xml rejected.xml bearer.xml s6a_attach.xml "$OUT/"
cp ../../sipp_scenarios/s6a_roaming_not_allowed.xml "$OUT/"
sed 's/EXPECT/5004/' s6a_denied.xml > "$OUT/s6a_denied.xml"
sed 's/EXPECT/2001/' s6a_denied.xml > "$OUT/s6a_denied_unexpected.xml"
sed 's/TIMEOUT/5000/' s6a_cancel.xml > "$OUT/s6a_cancel.xml"
sed 's/TIMEOUT/500/' s6a_cancel.xml > "$OUT/s6a_cancel_short.xml"
for last in 404 504 317; do printf 'SEQUENTIAL\n001010000000%s;x;ims\n' $last > "$OUT/user$last.csv"; done
chmod -R a+rX "$OUT"

docker run -d --name "$PGW" --entrypoint sleep s8-standin-pgw 600 >/dev/null
PGW_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$PGW")
docker exec -d "$PGW" sh -c "python3 /standin_pgw.py $PGW_IP > /tmp/pgw.log 2>&1"
docker exec -d "$PGW" sh -c "python3 /standin_hss.py $PGW_IP tcp > /tmp/hss.log 2>&1"
docker run -d --name "$UE" --cap-add NET_ADMIN --device /dev/net/tun \
    -v "$OUT:/t" -w /tmp --entrypoint sleep "$SIPP_IMAGE" 600 >/dev/null
sleep 2

sipp() {    # sipp <scenario> <calls> <rate> [more options]; INF=<file> for other users
    sc=$1; m=$2; r=$3; shift 3
    docker exec "$UE" sipp -sf "/t/$sc" -inf "/t/${INF:-users.csv}" -visited_plmn 00101 \
        -t un -m "$m" -r "$r" -max_socket 100 -timeout 30 -nostdin "$@" 10.88.0.1:5060 2>&1
}
count() {   # count <successful|failed> in a SIPp result screen
    grep -i "$1 call" | awk -F'|' '{gsub(/ /, "", $3); print $3}'
}
kernel_leftovers() {
    docker exec "$UE" sh -c 'echo "$(ip -br addr | grep -c "10\.99\.") $(ip rule | grep -c "from 10\.99\.") $(ip -br link | grep -c sipps8)"'
}

res=$(sipp session.xml 10 5 -s8_pgw "$PGW_IP")
check "10 UEs one after the other: session, REGISTER through GTP-U, delete" 10 "$(echo "$res" | count successful)"
check "  nothing left in the kernel" "0 0 0" "$(kernel_leftovers)"

res=$(sipp session.xml 10 100 -s8_pgw "$PGW_IP")
check "10 UEs in parallel" 10 "$(echo "$res" | count successful)"
check "  nothing left in the kernel" "0 0 0" "$(kernel_leftovers)"

res=$(sipp rejected.xml 1 1 -s8_pgw "$PGW_IP")
check "a rejection the scenario expects (cause 93) passes" 1 "$(echo "$res" | count successful)"

res=$(sipp rejected_unexpected.xml 1 1 -s8_pgw "$PGW_IP")
check "the same rejection fails a call that expects cause 16" 1 "$(echo "$res" | count failed)"

start=$(date +%s)
res=$(sipp session.xml 1 1 -s8_pgw 192.0.2.1 -s8_t3 1000 -s8_n3 2)
took=$(($(date +%s) - start))
check "no answer from the PGW fails the call" 1 "$(echo "$res" | count failed)"
check "  after T3 x (N3 + 1), about 3 s" yes "$([ $took -ge 3 ] && [ $took -le 6 ] && echo yes || echo "no: ${took}s")"

res=$(sipp bearer.xml 10 100 -s8_pgw "$PGW_IP")
check "10 UEs in parallel: dedicated bearer created, updated, deleted" 10 "$(echo "$res" | count successful)"
check "  nothing left in the kernel" "0 0 0" "$(kernel_leftovers)"

res=$(sipp no_bearer.xml 1 1 -s8_pgw "$PGW_IP")
check "waiting for a bearer that never comes fails the call" 1 "$(echo "$res" | count failed)"
res=$(sipp no_bearer_optional.xml 1 1 -s8_pgw "$PGW_IP")
check "  unless the scenario calls the bearer optional" 1 "$(echo "$res" | count successful)"

# --- S6a (stand-in HSS on the same address, Diameter over TCP) ---
S6A="-s6a_peer $PGW_IP -s6a_transport tcp -s6a_dest_realm epc.mnc024.mcc262.3gppnetwork.org"
res=$(sipp s6a_attach.xml 10 100 -s8_pgw "$PGW_IP" $S6A)
check "10 UEs in parallel: AIR, ULR, session with the HSS's data, REGISTER, delete, PUR" 10 "$(echo "$res" | count successful)"
check "  nothing left in the kernel" "0 0 0" "$(kernel_leftovers)"

res=$(INF=user504.csv sipp s6a_denied.xml 1 1 $S6A)
check "roaming not allowed (5004) passes a call that expects it" 1 "$(echo "$res" | count successful)"
res=$(INF=user504.csv sipp s6a_denied_unexpected.xml 1 1 $S6A)
check "  and fails one that expects success" 1 "$(echo "$res" | count failed)"
res=$(INF=user504.csv sipp s6a_roaming_not_allowed.xml 1 1 $S6A)
check "example scenario s6a_roaming_not_allowed.xml passes for a barred UE" 1 "$(echo "$res" | count successful)"
res=$(sipp s6a_roaming_not_allowed.xml 1 1 $S6A)
check "  and fails for a UE the HSS lets roam" 1 "$(echo "$res" | count failed)"
res=$(INF=user404.csv sipp s6a_attach.xml 1 1 -s8_pgw "$PGW_IP" $S6A)
check "unknown user (5001 on AIR) fails the call before any session" 1 "$(echo "$res" | count failed)"

res=$(INF=user317.csv sipp s6a_cancel.xml 1 1 -s8_pgw "$PGW_IP" $S6A)
check "Cancel Location during the session: awaited, then detached" 1 "$(echo "$res" | count successful)"
res=$(sipp s6a_cancel_short.xml 1 1 -s8_pgw "$PGW_IP" $S6A)
check "  a cancellation that does not come fails the waiting call" 1 "$(echo "$res" | count failed)"

start=$(date +%s)
res=$(sipp s6a_denied.xml 1 1 -s6a_peer 192.0.2.1 -s6a_transport tcp -s6a_dest_realm x.invalid)
took=$(($(date +%s) - start))
check "no Diameter peer fails the call" 1 "$(echo "$res" | count failed)"
check "  within the connect timeout" yes "$([ $took -le 8 ] && echo yes || echo "no: ${took}s")"
res=$(sipp s6a_denied.xml 1 1 -s6a_peer "$PGW_IP" -s6a_transport tcp)
check "S6a without a destination realm fails the call" 1 "$(echo "$res" | count failed)"

hlog=$(docker exec "$PGW" cat /tmp/hss.log)
check "HSS: capabilities exchange names the MME of the visited PLMN and S6a" yes "$(echo "$hlog" | grep -q 'CER origin_host=mmec01.mmegi0001.mme.epc.mnc001.mcc001.3gppnetwork.org origin_realm=epc.mnc001.mcc001.3gppnetwork.org .*s6a_advertised=True' && echo yes || echo no)"
check "HSS: ULR with visited PLMN 001/01, S6a + initial attach flags, E-UTRAN, IMEI and SV" 10 "$(echo "$hlog" | grep -c '^ULR imsi=0010100000000[01][0-9] .*;0010100000000[01][0-9] .*dest_realm=epc.mnc024.mcc262.3gppnetwork.org visited_plmn=00f110 proxiable=True ulr_flags=0x22 rat=1004 imei=35609204079054 sv=01$')"
check "HSS: every AIR carries the visited PLMN" 0 "$(echo "$hlog" | grep '^AIR ' | grep -vc 'visited_plmn=00f110')"
check "HSS: Purge UE after the session" 10 "$(echo "$hlog" | grep -c '^PUR imsi=0010100000000[01][0-9] ')"
check "HSS: Session-Ids are unique" 0 "$(echo "$hlog" | grep -o 'session_id=mme[^ ]*' | sort | uniq -d | wc -l)"
# An Insert Subscriber Data that reaches a SIPp which is just exiting stays unanswered
check "HSS: its Insert Subscriber Data requests are answered with success" yes "$([ "$(echo "$hlog" | grep -c '^IDA received result=2001 .*session_id=yes')" -ge 10 ] && [ "$(echo "$hlog" | grep '^IDA received' | grep -vc 'result=2001')" = 0 ] && echo yes || echo no)"
check "HSS: its Cancel Location is answered with success" 1 "$(echo "$hlog" | grep -c '^CLA received result=2001 .*session_id=yes')"
check "HSS: its watchdog requests are answered" yes "$([ "$(echo "$hlog" | grep -c '^DWA received result=2001')" -ge 5 ] && echo yes || echo no)"
check "HSS: no Purge UE after the cancellation" 0 "$(echo "$hlog" | grep -c '^PUR imsi=001010000000317')"

log=$(docker exec "$PGW" cat /tmp/pgw.log)
check "PGW: Create Session carries MSISDN, APN-AMBR, QCI and ARP from the HSS" 10 "$(echo "$log" | grep -c 'subscription: msisdn=49155500000[01][0-9] ambr_ul=384 ambr_dl=640 qci=5 arp=3$')"
blog=$(echo "$log" | grep -E 'BEARER TEST|BRsp')
check "PGW: Create Bearer accepted with the SGW's F-TEID, the PGW's echoed" 10 "$(echo "$blog" | grep -c 'CBRsp known=True cause=\[16\] bearer_cause=\[16\] ebi=\[6\] sgw_iface=4 .*pgw_fteid_echo=ok$')"
check "PGW: a retransmitted Create Bearer Request gets the same answer" 10 "$(echo "$blog" | grep -c 'retransmission=same answer')"
check "PGW: downlink TEIDs of the dedicated bearers are unique" 0 "$(echo "$blog" | grep -v retransmission | grep -o 'sgw_u_teid=0x[0-9a-f]*' | sort | uniq -d | wc -l)"
check "PGW: REGISTER 1 on the default bearer" 10 "$(echo "$blog" | grep -c 'CSeq: 1 REGISTER arrived on the default')"
check "PGW: REGISTER 2 meets the uplink filter: dedicated bearer" 10 "$(echo "$blog" | grep -c 'CSeq: 2 REGISTER arrived on the dedicated')"
check "PGW: REGISTER 3, filter replaced: default bearer" 10 "$(echo "$blog" | grep -c 'CSeq: 3 REGISTER arrived on the default')"
check "PGW: REGISTER 4, bearer deleted: default bearer" 10 "$(echo "$blog" | grep -c 'CSeq: 4 REGISTER arrived on the default')"
check "PGW: Update Bearer accepted" 10 "$(echo "$blog" | grep -c 'UBRsp known=True cause=\[16\] bearer_cause=\[16\] ebi=\[6\]')"
check "PGW: Delete Bearer accepted" 10 "$(echo "$blog" | grep -c 'DBRsp known=True cause=\[16\] bearer_cause=\[16\] ebi=\[6\]')"
check "PGW: sessions accepted" 44 "$(echo "$log" | grep -c -- '-> accepted')"
check "PGW: REGISTERs on a TEID it assigned" 70 "$(echo "$log" | grep -c 'matches session\|matches dedicated')"
check "PGW: packets on a TEID it does not know" 0 "$(echo "$log" | grep -c 'UNKNOWN')"
check "PGW: sessions deleted" 44 "$(echo "$log" | grep -c '^DSR.*known=True')"
check "PGW: no IE of a request it could not parse" 0 "$(echo "$log" | grep -c 'malformed=True')"
check "PGW: control plane TEIDs are unique" 0 "$(echo "$log" | grep -o 'sender F-TEID iface=6 teid=0x[0-9a-f]*' | sort | uniq -d | wc -l)"

[ $failed -eq 0 ] && echo "PASSED" || { echo "FAILED"; echo "$log" | tail -12; echo "$hlog" | tail -25; echo "$hlog" | grep -o "session_id=[^ ]*" | sort | uniq -d; }
exit $failed
