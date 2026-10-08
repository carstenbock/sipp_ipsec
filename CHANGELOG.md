# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- IPv6 and dual stack for S8 and SWu: `pdn_type="ipv6"` or `"ipv4v6"` on `<s8_create_session>` and `<swu_attach>` asks for an IPv6 prefix (PAA and PCO on S8; INTERNAL_IP6_ADDRESS, P_CSCF_IP6_ADDRESS and IPv6 traffic selectors on SWu), alone or next to an IPv4 address. SIP uses IPv6 when the network names an IPv6 P-CSCF (`sip_family=` overrides), with `[local_ip]`, `[remote_ip]`, `[local_ip_type]` and `[media_ip_type]` following; `[s8_ue_ip]` and `[s8_ue_ip6]` give both addresses. GTP-U carries IPv6 packets, and TFT packet filters with IPv6 addresses select the bearer. The transport to the PGW and the ePDG stays IPv4
- S8 home-routed roaming: SIPp can play the visited SGW toward a home PGW. `<s8_create_session imsi= msisdn= apn= ...>` opens a PDN connection over GTPv2-C (3GPP TS 29.274) at the PGW given with `-s8_pgw`, `<s8_delete_session/>` closes it; the UE's SIP and RTP then travel as IP packets inside GTP-U (TS 29.281) through a TUN device. `expect=` names the GTP cause a call accepts and `assign_to=` stores it, so rejections can be tested; `[s8_cause]`, `[s8_pgw_c_ip]`, `[s8_pgw_c_teid]`, `[s8_pgw_u_ip]` and `[s8_pgw_u_teid]` expose the result. New options `-s8_local_ip`, `-s8_t3`, `-s8_n3` and `-visited_plmn`. IPv4 only (see `docs/s8hr.rst`)
- S8 dedicated bearers: a Create, Update or Delete Bearer Request of the PGW is accepted without the scenario. Uplink packets that match a bearer's uplink TFT packet filters leave on that bearer's TEID, so a call's RTP travels on the voice bearer (QCI 1) the home network sets up. `<s8_wait_bearer qci= released= timeout= optional= assign_to=>` lets a scenario wait for a bearer to come or go
- S6a for the roaming tests: SIPp can play the visited MME toward the home HSS or its DRA (3GPP TS 29.272 on Diameter, over SCTP or TCP). `<s6a_auth>`, `<s6a_update_location>` and `<s6a_purge>` send AIR, ULR and PUR with the visited PLMN; `expect=` names the result a call accepts (e.g. `5004`, roaming not allowed) and `assign_to=` stores it. The subscription data of the Update Location Answer is available as `[s6a_msisdn]`, `[s6a_qci]`, `[s6a_arp]`, `[s6a_apn_ambr_ul]`, `[s6a_apn_ambr_dl]` and `[s6a_pdn_type]`, ready for `<s8_create_session>`. Cancel-Location, Insert- and Delete-Subscriber-Data, Reset and Device-Watchdog requests of the HSS are answered; `<s6a_wait_cancel>` waits for a cancellation. New options `-s6a_peer`, `-s6a_transport`, `-s6a_local_ip`, `-s6a_origin_host`, `-s6a_origin_realm`, `-s6a_dest_realm` and `-s6a_timeout`; Origin-Host and Origin-Realm default to the MME names of `-visited_plmn`
- `sipp_scenarios/s6a_s8hr_register.xml`: attach of a roaming UE with S6a and S8, then IMS registration
- Roaming example scenarios: `s6a_s8hr_uac.xml` / `s6a_s8hr_uas.xml` (attach with S6a and S8, IMS registration, call with RTP on the voice bearer, detach), `s6a_roaming_not_allowed.xml` (the HSS refuses the UE in the visited PLMN) and `s6a_s8hr_cancel_uac.xml` (Cancel Location during a call, UE detached without SIP)
- `sipp_scenarios/s8hr_uac.xml` and `s8hr_uas.xml`: MO and MT call of a roaming UE through its S8 bearers
- `sipp_scenarios/media/pcma_rtp.pcap`: one direction of PCMA RTP and nothing else, for scenarios whose media has to keep one source port (a voice bearer's packet filter names it)
- `sipp_scenarios/s8hr_register.xml`: IMS registration of a roaming UE through its S8 bearer
- A scenario with an access action (`<swu_attach>`, `<s8_create_session>`) but no SIP message runs in client mode instead of failing with "Unable to determine creation mode", so a test of the access procedure alone is possible
- VoWiFi calls: `sipp_scenarios/vowifi_uac.xml` (MO call with PCAP audio) and `vowifi_uas.xml` (MT call with RTP echo), each with SWu attach, IMS registration, de-registration and detach around the call
- VoWiFi media: PCAP play (`play_pcap_audio`, `play_pcap_video`, `play_dtmf`) sends from the call's inner address, so the RTP goes through the UE's SWu tunnel. With `-rtp_echo` and `-swu_epdg` the echo sockets listen on all addresses and answer from the one a packet arrived on, so every UE echoes on its own inner address
- VoWiFi: a call can attach to an ePDG before it registers. The new `<swu_attach identity= k= opc= apn=>` action builds the SWu tunnel (IKEv2 with EAP-AKA' or EAP-AKA, 3GPP TS 24.302 / TS 33.402) to the ePDG given with `-swu_epdg`, `<swu_detach/>` deletes it. After the attach `[local_ip]` and `[media_ip]` are the inner address the ePDG assigned and `[remote_ip]` the P-CSCF it named, and the IMS IPSec SAs are nested inside the tunnel. Needs `-t un`; IPv4 and SIP over UDP only, no rekeying (see `docs/swu.rst`)
- `sipp_scenarios/vowifi_register.xml`: SWu attach, IMS registration with IPSec, de-registration and SWu detach, one UE per line of the injection file
- `sipp.dtd` declares the `ipsec_setup`, `ipsec_teardown`, `swu_attach` and `swu_detach` actions
- `-ipsec_port_min` / `-ipsec_port_max` set the range for UE protected ports (port-c/port-s, TS 33.203); each concurrent UE uses two ports, so the range caps UEs per source IP (default 32768-65535)
- RFC 3608 Service-Route extraction in all VoLTE scenarios: `Service-Route` from REGISTER 200 OK is captured and used as preloaded `Route` in subsequent originated requests (INVITE, PRACK, ACK, BYE)
- Full IMS REGISTER/401/IPSec/REGISTER/200 phase added to `volte_uas_template.xml`, `volte_mixed_load.xml`, and `volte_routing_probe.xml` (previously started without registration)
- De-REGISTER (`Expires: 0`) + `ipsec_teardown` appended to `volte_uas_template.xml`, `volte_mixed_load.xml`, and `volte_routing_probe.xml`
- `sipp_scenarios/README.md`: scenario overview, usage table, common parameters, and quick-start examples
- `docs/volte_scenarios.rst`: detailed Sphinx documentation for all VoLTE scenarios with CLI examples and troubleshooting
- New VoLTE scenario templates: `volte_uac_template.xml` (MO call with 180/183+PRACK handling from real iOS trace), `volte_uas_template.xml` (MT call with rtp_echo), `volte_routing_probe.xml`, `volte_reregister_cycle.xml`, `volte_mixed_load.xml`
- `apps/sipp/sipp_scenarios/media/` directory: RTP PCAP files (`evs-ue-side.pcap`, `g722-gw-side.pcap`) moved from repo root; `amr-wb.pcap`, `amr-nb.pcap`, `pcmu.pcap`, `pcma.pcap` from nesfit/Codecs
- `apps/sipp/sipp_scenarios/traces/` directory: `mo-call-1.pcap` (iOS 26.3.1 reference trace) moved from repo root
- `docker/Dockerfile`: `USE_IPSEC=1` build argument enables `-DUSE_IPSEC=1` CMake flag; `iproute2` added to runtime image for XFRM SA management

### Changed
- The ESP tunnel SAs of an SWu attach accept inner packets of both address families (`XFRM_STATE_AF_UNSPEC`); a PGW's answer "accepted with another PDN type" (GTP causes 17 to 19) brings an S8 session up like cause 16
- VoLTE scenarios now use Service-Route from REGISTER 200 OK as `Route` header instead of hardcoded `Route: <sip:[remote_ip]:[remote_port];lr>`
- `volte_reregister_cycle.xml` re-extracts Service-Route on every refresh 200 OK to handle registrar route updates
- Security-Client header now offers all 4 algorithm combinations ({hmac-md5-96, hmac-sha-1-96} x {aes-cbc, null}) per 3GPP TS 33.203, matching real UE behavior
- IPSec protected ports (port-c, port-s) now use random ephemeral ports (32768-65535) instead of hardcoded 5060/5061

### Fixed
- A request with a new Call-ID that arrives on a UE's protected server port (an INVITE to a registered UE) is handed to the call that owns the port instead of being discarded as "can't be mapped to a known SIPp call", so the callee scenarios (`vowifi_uas.xml`, `s8hr_uas.xml`) receive their call
- IMS IPSec SAs and policies no longer name a transport protocol (3GPP TS 33.203 protects UDP and TCP between the four ports). A P-CSCF that opens TCP to the protected server port for a large request (RFC 3261 section 18.1.1) now gets a reset and can fall back to UDP at once; before, its SYN was dropped by the SA selector and the request (seen with a BYE) timed out
- `vowifi_uas.xml`: removed an `<exec rtp_echo="true"/>` action that is not valid and ended SIPp with "unknown action" on the first INVITE; `-rtp_echo` alone starts the echo
- `vowifi_uac.xml` plays `media/pcma_rtp.pcap`: `pcma.pcap` holds a whole call (SIP and both RTP directions), which PCAP play sent out as media from several source ports
- IPSec: policies were left in the kernel at the end of a call, at random (`xfrm netlink response error: No such file or directory`, `Some IPSec SAs/policies could not be removed`). IPv4 addresses were written into the 16-byte selector fields without clearing them, and the kernel finds the policy to delete by comparing the whole selector. A leftover policy makes the next UE on the same address and ports fail
- IPSec: every call opened the XFRM netlink socket again and the first call to end closed it, after which no other call could remove its SAs and policies (`XFRM netlink not initialized`). The socket is now opened once and kept
- `volte_register.xml` did not start: `service_route` was assigned but never used, which SIPp rejects (`Variable $service_route is referenced 1 times!`); the scenario now declares it with `<Reference>`
- IPSec with `-t ui`: the protected sockets (port-c/port-s) and the SAs now use the call's own address from `-ip_field` instead of the process-wide `-i` address, so several UEs with different source IPs can register from one SIPp process
- IPSec: a call's protected client socket was closed twice when the call ended (once by `~call`, once by `~socketowner`, after the first close had deleted it), which aborted SIPp with `malloc(): unaligned tcache chunk detected` as soon as the first IPSec call failed or de-registered. The call now gives the socket up before closing it, and the switch to the protected socket removes the call from the old socket's owner list
- IPSec protected ports are taken from a per-process pool and returned when the call ends, instead of drawn at random with no in-use check; two UEs on one source IP could get the same port and the second UE's protected socket failed to bind (a generator-side failure from a few hundred UEs per IP upward)
- VoLTE scenarios: in-dialog requests (ACK, BYE) now use the Record-Route set from INVITE responses (`rrs="true"` + `[routes]`) instead of the Service-Route from registration, per RFC 3261 §12.1.2; Request-URI uses `[next_url]` (remote Contact) instead of hardcoded addresses; UAS template echoes `[last_Record-Route:]` in 180/200 responses
- VoLTE scenarios: use `///` prefix instead of `-suffix` for multi-dialog Call-IDs so SIPp's listener lookup matches responses (fixes INVITE 200 OK and REGISTER responses silently discarded as out-of-call messages)
- Create listening socket on UE server port (`port_us`) so P-CSCF responses per 3GPP TS 33.203 are received (fixes ICMP port unreachable)
- `[local_port]` keyword now resolves to the IPSec client port (`port_uc`) when IPSec is active, so Via/Contact headers advertise the correct protected port
- First IPSec-protected REGISTER (same `<send>` as `[authentication]`) now uses correct IPSec ports in Via/Contact/Route instead of the pre-activation port (e.g. 5060)
- IPSec socket now inherits `-bind_to_device` setting; ESP packets no longer go out on the wrong interface
- Docker build (Dockerfile.ipsec) now copies `third_party` so bundled pugixml is available; fixes "Cannot find source file third_party/pugixml/src/pugixml.cpp"
