# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- New VoLTE scenario templates: `volte_uac_template.xml` (MO call with 180/183+PRACK handling from real iOS trace), `volte_uas_template.xml` (MT call with rtp_echo), `volte_routing_probe.xml`, `volte_reregister_cycle.xml`, `volte_mixed_load.xml`
- `apps/sipp/sipp_scenarios/media/` directory: RTP PCAP files (`evs-ue-side.pcap`, `g722-gw-side.pcap`) moved from repo root; `amr-wb.pcap`, `amr-nb.pcap`, `pcmu.pcap`, `pcma.pcap` from nesfit/Codecs
- `apps/sipp/sipp_scenarios/traces/` directory: `mo-call-1.pcap` (iOS 26.3.1 reference trace) moved from repo root
- `docker/Dockerfile`: `USE_IPSEC=1` build argument enables `-DUSE_IPSEC=1` CMake flag; `iproute2` added to runtime image for XFRM SA management

### Fixed
- Docker build (Dockerfile.ipsec) now copies `third_party` so bundled pugixml is available; fixes "Cannot find source file third_party/pugixml/src/pugixml.cpp"
