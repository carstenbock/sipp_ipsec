# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
- VoLTE scenarios now use Service-Route from REGISTER 200 OK as `Route` header instead of hardcoded `Route: <sip:[remote_ip]:[remote_port];lr>`
- `volte_reregister_cycle.xml` re-extracts Service-Route on every refresh 200 OK to handle registrar route updates
- Security-Client header now offers all 4 algorithm combinations ({hmac-md5-96, hmac-sha-1-96} x {aes-cbc, null}) per 3GPP TS 33.203, matching real UE behavior
- IPSec protected ports (port-c, port-s) now use random ephemeral ports (32768-65535) instead of hardcoded 5060/5061

### Fixed
- VoLTE scenarios: in-dialog requests (ACK, BYE) now use the Record-Route set from INVITE responses (`rrs="true"` + `[routes]`) instead of the Service-Route from registration, per RFC 3261 §12.1.2; Request-URI uses `[next_url]` (remote Contact) instead of hardcoded addresses; UAS template echoes `[last_Record-Route:]` in 180/200 responses
- VoLTE scenarios: use `///` prefix instead of `-suffix` for multi-dialog Call-IDs so SIPp's listener lookup matches responses (fixes INVITE 200 OK and REGISTER responses silently discarded as out-of-call messages)
- Create listening socket on UE server port (`port_us`) so P-CSCF responses per 3GPP TS 33.203 are received (fixes ICMP port unreachable)
- `[local_port]` keyword now resolves to the IPSec client port (`port_uc`) when IPSec is active, so Via/Contact headers advertise the correct protected port
- First IPSec-protected REGISTER (same `<send>` as `[authentication]`) now uses correct IPSec ports in Via/Contact/Route instead of the pre-activation port (e.g. 5060)
- IPSec socket now inherits `-bind_to_device` setting; ESP packets no longer go out on the wrong interface
- Docker build (Dockerfile.ipsec) now copies `third_party` so bundled pugixml is available; fixes "Cannot find source file third_party/pugixml/src/pugixml.cpp"
