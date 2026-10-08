# VoLTE SIPp Scenarios

SIPp scenario files for testing VoLTE/IMS signaling over IPSec.

All VoLTE scenarios follow the 3GPP IMS registration flow with IPSec
security mechanism agreement (sec-agree) per TS 33.203, and implement
[RFC 3608](https://datatracker.ietf.org/doc/html/rfc3608) Service-Route
discovery during registration.

## Common Flow

Every VoLTE scenario follows this registration pattern:

```
UE                          P-CSCF / IMS
 |                               |
 |--- REGISTER (unprotected) --->|   Security-Client, stub Authorization
 |<-- 401 Unauthorized ----------|   WWW-Authenticate (AKA), Security-Server
 |                               |
 |   [IPSec SA setup via XFRM]  |
 |                               |
 |--- REGISTER (over IPSec) ---->|   Authorization (AKA digest), Security-Verify
 |<-- 200 OK --------------------|   Service-Route: <sip:pcscf;lr>,<sip:scscf;lr>
 |                               |
 |   [Store Service-Route]       |
 |                               |
 |--- INVITE ------------------->|   Route: <Service-Route value>
 |<-- 200 OK --------------------|   Record-Route: <sip:scscf;lr>,<sip:pcscf;lr>
 |                               |
 |   [Build dialog route set     |
 |    from Record-Route]         |
 |                               |
 |--- ACK ---------------------->|   Route: <Record-Route set (reversed)>
 |   ...media...                 |
 |--- BYE ---------------------->|   Route: <Record-Route set (reversed)>
 |                               |
 |--- REGISTER (Expires: 0) ---->|   De-registration
 |<-- 200 OK --------------------|
 |   [IPSec SA teardown]         |
```

The `Service-Route` header returned in the REGISTER 200 OK is extracted
and used as a preloaded `Route` header in the initial INVITE, per
RFC 3608 Section 6.1. Once the INVITE dialog is established, in-dialog
requests (ACK, BYE) use the `Record-Route` set from the INVITE 200 OK
response instead, per RFC 3261 Section 12.1.2. SIPp's `rrs="true"`
attribute on `<recv>` captures the Record-Route headers, and the
`[routes]` keyword expands to the reversed route set in subsequent
`<send>` steps.

## Scenarios

| Scenario | Purpose | Flow |
|----------|---------|------|
| `volte_register.xml` | Basic IMS registration test | REGISTER/401/IPSec/REGISTER/200 + de-REGISTER |
| `volte_uac_template.xml` | MO (Mobile Originated) call | REGISTER + INVITE + media + BYE + de-REGISTER |
| `volte_uas_template.xml` | MT (Mobile Terminated) call | REGISTER + wait for INVITE + answer + BYE + de-REGISTER |
| `volte_mixed_load.xml` | CSV-driven load test | REGISTER + INVITE (from CSV) + media + BYE + de-REGISTER |
| `volte_reregister_cycle.xml` | Registration refresh stress test | REGISTER + re-REGISTER cycle + de-REGISTER |
| `volte_routing_probe.xml` | SBC routing validation | REGISTER + INVITE (no media) + CANCEL/BYE + de-REGISTER |
| `s8hr_register.xml` | IMS registration of a roaming UE (S8 home-routed) | S8 Create Session at the home PGW + REGISTER/401/IPSec/REGISTER/200 through GTP-U + de-REGISTER + Delete Session |
| `s6a_s8hr_register.xml` | Attach and IMS registration of a roaming UE, SIPp as visited MME and SGW | S6a AIR + ULR at the home HSS, S8 Create Session with the subscribed MSISDN/QoS/APN-AMBR, REGISTER/401/IPSec/REGISTER/200 through GTP-U, de-REGISTER, Delete Session, S6a PUR |
| `s6a_s8hr_uac.xml` | MO call of a roaming UE, SIPp as visited MME and SGW | S6a AIR + ULR, S8 Create Session with the subscribed values, IMS registration with IPSec, INVITE, RTP on the dedicated voice bearer, BYE, de-REGISTER, Delete Session, S6a PUR |
| `s6a_s8hr_uas.xml` | MT call to a roaming UE, SIPp as visited MME and SGW | Same attach and registration, answers an INVITE and echoes RTP (`-rtp_echo`) on the voice bearer |
| `s6a_roaming_not_allowed.xml` | Roaming refused by the home HSS | S6a AIR, then ULR; passes when one of them is answered with 5004, fails on success. No PDN connection, no SIP |
| `s6a_s8hr_cancel_uac.xml` | Cancel Location during a call | As `s6a_s8hr_uac.xml`, then waits for the HSS's Cancel-Location-Request and detaches the UE without SIP (Delete Session only); normal call end if none comes within `cancel_wait` |
| `s8hr_uac.xml` | MO call of a roaming UE (S8 home-routed) | S8 Create Session + IMS registration with IPSec + INVITE + RTP on the dedicated voice bearer the PGW creates + BYE + de-REGISTER + Delete Session |
| `s8hr_uas.xml` | MT call to a roaming UE (S8 home-routed) | Same access and registration, answers an INVITE and echoes RTP (`-rtp_echo`) on the voice bearer |
| `vowifi_uac.xml` | VoWiFi MO call | SWu attach + REGISTER + INVITE (PRACK when the 183 is reliable) + PCAP audio from the UE's inner address + BYE + de-REGISTER + SWu detach |
| `vowifi_uas.xml` | VoWiFi MT call | SWu attach + REGISTER + wait for INVITE + answer + RTP echo from the UE's inner address + BYE + de-REGISTER + SWu detach |
| `vowifi_register.xml` | IMS registration over untrusted WLAN | SWu attach to the ePDG (IKEv2, EAP-AKA' or EAP-AKA) + REGISTER/401/IPSec/REGISTER/200 + de-REGISTER + SWu detach |

## Prerequisites

- SIPp built with `-DUSE_IPSEC=1` (see main [README](../README.md))
- Root privileges or `CAP_NET_ADMIN` for XFRM SA creation
- AKA credentials: K, OP (or pre-computed OPc), AMF
- Network connectivity to the P-CSCF

## Common Parameters

| Parameter | Flag | Description |
|-----------|------|-------------|
| IMSI | `-s <imsi>` | Private user identity (used for REGISTER) |
| Domain | `-key domain <realm>` | IMS home domain (e.g. `ims.mnc001.mcc001.3gppnetwork.org`) |
| MSISDN | `-key msisdn <number>` | Public user identity (used in INVITE From/P-Preferred-Identity) |
| AKA K | `-key aka_K <hex>` | Subscriber authentication key |
| AKA OP | `-key aka_OP <hex>` | Operator key (raw) |
| AKA OPc | `-key aka_OPc <hex>` | Operator key (pre-computed, use instead of OP) |
| AKA AMF | `-key aka_AMF <hex>` | Authentication Management Field |

## Quick Start

### Basic Registration Test

```bash
sudo ./sipp -sf sipp_scenarios/volte_register.xml -ipsec \
    -s 001010000000001 \
    -key domain ims.mnc001.mcc001.3gppnetwork.org \
    -au 001010000000001 \
    -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
    -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
    -key aka_AMF 0x8000 \
    192.168.1.1:5060
```

### MO Call (UAC)

The UAC template uses placeholders (`__DOMAIN__`, `__TARGET_URI__`,
`__SDP_OFFER__`, etc.) that are replaced by the scenario generator at
build time. For direct use, replace them in the XML or use a wrapper
script.

### MT Call (UAS)

```bash
sudo ./sipp -sf sipp_scenarios/volte_uas_template.xml -ipsec \
    -s 001010000000001 \
    -key domain ims.mnc001.mcc001.3gppnetwork.org \
    -key msisdn 494034927217 \
    -key call_duration_ms 10000 \
    -au 001010000000001 \
    -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
    -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
    -key aka_AMF 0x8000 \
    -p 6060 \
    192.168.1.1:5060
```

### Routing Probe

```bash
sudo ./sipp -sf sipp_scenarios/volte_routing_probe.xml -ipsec \
    -s 001010000000001 \
    -key domain ims.mnc001.mcc001.3gppnetwork.org \
    -key msisdn 494034927217 \
    -key target_uri "tel:+4989200011251" \
    -au 001010000000001 \
    -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
    -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
    -key aka_AMF 0x8000 \
    192.168.1.1:5060
```

### Mixed Load (CSV-Driven)

```bash
sudo ./sipp -sf sipp_scenarios/volte_mixed_load.xml -ipsec \
    -inf mixed_load.csv \
    -s 001010000000001 \
    -au 001010000000001 \
    -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
    -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
    -key aka_AMF 0x8000 \
    -l 100 -r 5 \
    192.168.1.1:5060
```

CSV format (no header row):

```
scenario,target_uri,domain,calling_msisdn,ue_codec_pt,gw_codec_pt,call_duration_ms,imsi
```

Example row:

```
ue_to_gw,tel:+4989200011251,ims.mnc001.mcc001.3gppnetwork.org,494034927217,116,9,8000,001019999900001
```

### VoWiFi Registration via an ePDG

One UE per line in `users.csv` (`<imsi>;<K hex>;<OPc hex>`). `eap_prefix` selects the EAP method: `6` for EAP-AKA', `0` for EAP-AKA. See `docs/swu.rst`.

```bash
sudo ./sipp -sf sipp_scenarios/vowifi_register.xml \
    -swu_epdg <epdg_ip> -ipsec -t un -inf users.csv \
    -key eap_prefix 6 \
    -key domain ims.mnc001.mcc001.3gppnetwork.org \
    -key nai_realm nai.epc.mnc001.mcc001.3gppnetwork.org \
    -key wlan_node_id 001122334455 \
    <pcscf_ip>:5060
```

### VoWiFi Call (MO and MT)

Callee first, in one SIPp; then the caller in another. `callees.csv` holds `<imsi>;<K>;<OPc>;<own MSISDN>`, `callers.csv` additionally `;<target URI>`. `-d` is the call duration in ms.

```bash
sudo ./sipp -sf sipp_scenarios/vowifi_uas.xml -rtp_echo \
    -swu_epdg <epdg_ip> -ipsec -t un -inf callees.csv \
    -key eap_prefix 6 \
    -key domain ims.mnc001.mcc001.3gppnetwork.org \
    -key nai_realm nai.epc.mnc001.mcc001.3gppnetwork.org \
    -key wlan_node_id 001122334455 \
    <pcscf_ip>:5060

sudo ./sipp -sf sipp_scenarios/vowifi_uac.xml -d 10000 \
    -swu_epdg <epdg_ip> -ipsec -t un -inf callers.csv \
    -key eap_prefix 6 \
    -key domain ims.mnc001.mcc001.3gppnetwork.org \
    -key nai_realm nai.epc.mnc001.mcc001.3gppnetwork.org \
    -key wlan_node_id 001122334455 \
    <pcscf_ip>:5060
```

### Docker

```bash
docker run --rm --cap-add=NET_ADMIN --net=host sipp-ipsec \
    -sf /scenarios/volte_register.xml -ipsec \
    -s 001010000000001 \
    -key domain ims.mnc001.mcc001.3gppnetwork.org \
    -au 001010000000001 \
    -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
    -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
    -key aka_AMF 0x8000 \
    192.168.1.1:5060
```

## Other Scenarios

This directory also contains non-VoLTE scenarios:

- `pfca_uac_*.xml` / `pfca_uas_*.xml` -- Enterprise UAC/UAS call flows
  with SRTP crypto variants (audio/video patterns A/B/V)
- `uc360_register*.xml` -- UC360-style registration (with/without 401 challenge)
- `mcd_register.xml` -- Mitel 3300-style REGISTER responder (UAS)
- `media/` -- RTP PCAP files and `convert_pcap_linktype.py` helper

## References

- [RFC 3261 -- SIP: Session Initiation Protocol](https://datatracker.ietf.org/doc/html/rfc3261) (Section 12.1.2: dialog route set from Record-Route)
- [RFC 3608 -- Service-Route Discovery During Registration](https://datatracker.ietf.org/doc/html/rfc3608)
- [RFC 3329 -- Security Mechanism Agreement for SIP](https://datatracker.ietf.org/doc/html/rfc3329)
- [3GPP TS 33.203 -- Access security for IP-based services](https://www.3gpp.org/DynaReport/33203.htm)
- [3GPP TS 24.229 -- IP multimedia call control protocol](https://www.3gpp.org/DynaReport/24229.htm)
