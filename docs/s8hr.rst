S8 Home-Routed Roaming (S8HR)
=============================

SIPp can play the visited network toward a home core, to test S8
home-routed roaming from the home operator's side: PGW, PCRF and IMS,
and how they treat a UE whose bearer comes from another network's SGW.
Each call is one roaming UE. SIPp opens its PDN connection at the home
PGW over S8 (GTPv2-C, 3GPP TS 29.274) and sends the UE's SIP and RTP to
the PGW as IP packets inside GTP-U (TS 29.281).

The feature is built whenever SIPp is built with ``-DUSE_IPSEC=ON`` on
Linux. At runtime it needs root or ``CAP_NET_ADMIN``, and
``/dev/net/tun``.

Status: Create and Delete Session, the default bearer, dedicated bearers
the PGW creates, updates and deletes, and the MME's side of S6a toward
the home HSS (this page).


Usage
`````

``-s8_pgw <host[:port]>``
    The home PGW's GTP-C address (default port 2123).

``-s8_local_ip <addr>``
    SIPp's S8 address: GTP-C (UDP 2123) and GTP-U (UDP 2152) are bound
    to it, and it is the address in the F-TEIDs. The PGW must reach it
    without NAT. Default: the ``-i`` address.

``-visited_plmn <mccmnc>``
    Visited PLMN, e.g. ``00101`` or ``310410``: Serving Network and the
    PLMN of TAI and ECGI in the User Location Information.

``-s8_t3 <ms>``, ``-s8_n3 <n>``
    T3-RESPONSE and N3-REQUESTS (TS 29.274 section 7.6): a request is
    sent again every T3 until answered, N3 times at most. Defaults 3000
    and 3.

``<s8_create_session imsi="..." .../>``
    Sends the Create Session Request. It must be the first step of a
    call, inside a ``<nop>``; the call waits there for the response.

    ===========  ==========  ==========================================
    Attribute    Default     Meaning
    ===========  ==========  ==========================================
    imsi         (required)  IMSI
    msisdn                   MSISDN, a leading ``+`` is ignored
    mei                      IMEI or IMEISV
    apn          ims         Access Point Name
    plmn         option      Visited PLMN, overrides ``-visited_plmn``
    qci          5           QCI of the default bearer
    arp          9           ARP priority level of the default bearer
    ambr_ul      1000000     APN-AMBR uplink, kbit/s
    ambr_dl      1000000     APN-AMBR downlink, kbit/s
    tac          1           Tracking area code (ULI)
    eci          1           E-UTRAN cell identifier (ULI)
    expect       16          GTP cause that lets the call go on; ``any``
                             accepts every outcome
    assign_to                Variable that receives the cause
    ===========  ==========  ==========================================

``<s8_delete_session expect="16" assign_to="..."/>``
    Sends the Delete Session Request and waits for the response. A call
    that ends without it deletes its session as well, without waiting.

All attributes may contain keywords such as ``[field0]``. The cause of a
request that got no answer is ``-1``.

After a successful Create Session:

====================  =================================================
``[local_ip]``        the UE address from the PAA
``[media_ip]``        the same address
``[remote_ip]``       the P-CSCF from the PCO; the ``remote_host`` of
                      the command line is used only if there is none
``[s8_cause]``        cause of the last response
``[s8_pgw_c_ip]``     PGW S5/S8 GTP-C address ...
``[s8_pgw_c_teid]``   ... and TEID
``[s8_pgw_u_ip]``     PGW S5/S8 GTP-U address ...
``[s8_pgw_u_teid]``   ... and TEID of the default bearer
====================  =================================================

``-t un`` is required. IMS IPSec (``-ipsec``), PCAP play and
``-rtp_echo`` work as for VoWiFi, see :doc:`swu`.

Registration of roaming UEs from ``users.csv``
(``<imsi>;<K>;<OPc>;<MSISDN>`` per line)::

    sudo ./sipp -sf sipp_scenarios/s8hr_register.xml \
        -s8_pgw 10.0.1.10 -s8_local_ip 10.0.2.15 -visited_plmn 00101 \
        -ipsec -t un -inf users.csv \
        -key domain ims.mnc024.mcc262.3gppnetwork.org \
        -key tac 1 -key eci 0x15ee001 -key cell_id 00101000115ee001 \
        10.0.1.20:5060

A test that the PGW refuses an unknown APN, with no SIP at all::

    <nop><action>
      <s8_create_session imsi="[field0]" apn="nosuchapn" expect="93"/>
    </action></nop>

To branch instead of failing, use ``expect="any" assign_to="cause"`` and
test ``cause`` in the next element.


Dedicated bearers
`````````````````

The home network sets up a dedicated bearer when it needs one, for a
VoLTE call the voice bearer with QCI 1 once the P-CSCF has told the PCRF
about the media. SIPp answers these requests of the PGW by itself:

Create Bearer Request
    Accepted. SIPp assigns the lowest free EPS bearer id (6 to 15) and a
    downlink TEID of its own, and answers with its S5/S8-U SGW F-TEID and
    the PGW's F-TEID echoed. From then on uplink packets that match one of
    the bearer's uplink packet filters (TFT, TS 24.008 clause 10.5.6.12)
    leave with the PGW's TEID for that bearer; everything else stays on
    the default bearer. Downlink is accepted on either TEID.

Update Bearer Request
    Accepted. A TFT in it is applied to the bearer's filters (create,
    add, replace, delete filters, delete TFT); a new QCI is noted.

Delete Bearer Request
    Accepted. A dedicated bearer is removed; with the linked EBI of the
    default bearer the whole PDN connection ends.

A retransmitted request gets the answer of the first one and is not
carried out twice. SIPp logs each bearer when it comes and goes, with the
number of packets it carried (``-trace_logs``)::

    13:25:05.912 S8 <imsi>: dedicated bearer EBI 6 (QCI 1) created, 4 packet filters, PGW-U 10.0.1.2 TEID 0x3005, local TEID 0x10330002
    S8 <imsi>: EBI 6 filter 0 uplink, precedence 0: protocol 17, local 10.46.0.5 port 6000-6000, remote 203.0.113.9 port 20040-20040
    ...
    13:25:14.031 S8 <imsi>: dedicated bearer EBI 6 (QCI 1) deleted by the PGW, carried 398 uplink and 397 downlink packets

A scenario that depends on the bearer waits for it::

    <nop><action>
      <s8_wait_bearer qci="1" timeout="3000" assign_to="ebi"/>
    </action></nop>

.. table::

    ===========  ==========  ================================================
    Attribute    Default     Meaning
    ===========  ==========  ================================================
    qci          any         wait for a dedicated bearer with this QCI
    released     false       ``true``: wait until no such bearer is left
    timeout      5000        milliseconds to wait
    optional     false       ``true``: go on when the time is up, instead of
                             failing the call
    assign_to                variable for the bearer's EBI, 0 if there is none
    ===========  ==========  ================================================

The filter components SIPp evaluates are IPv4 remote and local address,
protocol, and single or range local and remote port. A filter with any
other component (IPv6, SPI, type of service, flow label) selects nothing.
Later fragments of a packet have no ports and stay on the default bearer
when a filter names ports.

``sipp_scenarios/s8hr_uac.xml`` and ``s8hr_uas.xml`` are a caller and a
callee that register, set up a call and exchange RTP on the voice bearer.


S6a: the MME toward the home HSS
````````````````````````````````

Before a visited network asks the home PGW for a bearer, its MME has
authenticated the UE and registered itself at the home HSS over S6a
(3GPP TS 29.272), usually through Diameter agents. SIPp plays that MME
too, so the HSS's roaming decisions and the subscription data it hands
out are part of the test.

::

    -s6a_peer <host[:port]>   the home network's DRA, or its HSS (port 3868)
    -s6a_dest_realm <realm>   Destination-Realm: the realm of the home HSS
    -s6a_transport sctp|tcp   default sctp
    -s6a_origin_host <name>   default mmec01.mmegi0001.mme.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
    -s6a_origin_realm <realm> default epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org
    -s6a_timeout <ms>         wait for an answer, default 5000

The defaults for Origin-Host and Origin-Realm are the names of the
visited PLMN given with ``-visited_plmn`` (TS 23.003 clause 19); the same
PLMN goes into the Visited-PLMN-Id of the requests. A network that does
not use the ``epc.`` realms needs the options.

.. table::

    ==========================  ==================================================
    Action                      What it does
    ==========================  ==================================================
    ``<s6a_auth>``              Authentication-Information-Request for one E-UTRAN
                                vector. The vector itself is not used: there is
                                no NAS.
    ``<s6a_update_location>``   Update-Location-Request (E-UTRAN, initial attach).
                                The answer's subscription data for the APN named
                                with ``apn`` (default ``ims``) fills the keywords
                                below. ``mei`` adds the Terminal-Information.
    ``<s6a_purge>``             Purge-UE-Request, after the UE has detached.
    ``<s6a_wait_cancel>``       Waits for a Cancel-Location-Request of the HSS
                                (``timeout`` in ms, default 5000; ``optional``).
                                ``assign_to`` gets the Cancellation-Type, or -1.
    ==========================  ==================================================

The first of these actions in a call names the subscriber with ``imsi``.
Each waits for the HSS's answer. ``expect`` is the result the call has to
meet: ``2001`` by default, another code to test a refusal, or ``any``;
``assign_to`` stores it. Result-Code and Experimental-Result-Code are
treated alike, -1 means that no answer came::

    <nop><action>
      <s6a_auth imsi="[field0]"/>
    </action></nop>
    <nop><action>
      <s6a_update_location expect="5004"/>   <!-- roaming not allowed -->
    </action></nop>

.. table::

    =====================  ===================================================
    Keyword                Value
    =====================  ===================================================
    ``[s6a_result]``       result of the last S6a answer
    ``[s6a_msisdn]``       MSISDN from the subscription data, digits
    ``[s6a_qci]``          QCI of the APN's default bearer
    ``[s6a_arp]``          its ARP priority level
    ``[s6a_apn_ambr_ul]``  APN-AMBR uplink in kbit/s (S6a carries bit/s)
    ``[s6a_apn_ambr_dl]``  APN-AMBR downlink in kbit/s
    ``[s6a_pdn_type]``     0 IPv4, 1 IPv6, 2 IPv4v6, 3 IPv4 or IPv6
    =====================  ===================================================

They fit the attributes of ``<s8_create_session>`` as they are, which is
how an MME and SGW build the Create Session Request::

    <s8_create_session imsi="[field0]" msisdn="[s6a_msisdn]" apn="ims"
                       qci="[s6a_qci]" arp="[s6a_arp]"
                       ambr_ul="[s6a_apn_ambr_ul]" ambr_dl="[s6a_apn_ambr_dl]"/>

``sipp_scenarios/s6a_s8hr_register.xml`` is the whole attach: AIR, ULR,
Create Session, IMS registration, and back.

Requests of the HSS are answered without the scenario: Cancel-Location,
Insert-Subscriber-Data, Delete-Subscriber-Data and Reset with success,
Device-Watchdog as the base protocol wants it; each is logged
(``-trace_logs``). A Cancel-Location is remembered for
``<s6a_wait_cancel>``; SIPp does not detach the UE by itself, the
scenario does (BYE, de-registration, ``<s8_delete_session/>``, and no
Purge UE after a cancellation). Subscription data of an
Insert-Subscriber-Data is not applied.

All calls share one Diameter connection, opened with the first request
(capabilities exchange with the S6a application, vendor 10415). Every
request is a Diameter session of its own, as S6a keeps no session state;
Session-Ids are ``<origin-host>;<start time>;<counter>;<imsi>``. Over
SCTP the payload protocol identifier is 46. A lost connection fails the
requests in flight and is opened again with the next one; there is no
second peer and no failover.


How it works
````````````

* One GTP-C socket on ``<s8 address>:2123`` serves all calls. Responses
  are matched to requests by sequence number; requests of the PGW are
  routed by the TEID SIPp gave it. Each session has its own control and
  user plane TEID.
* Create Session Request carries IMSI, MSISDN, MEI, ULI (TAI and ECGI),
  Serving Network, RAT type E-UTRAN, the sender F-TEID (S5/S8 SGW
  GTP-C), APN, PDN type IPv4, PAA, APN-AMBR, a PCO asking for the P-CSCF
  and DNS addresses, and one bearer context with EBI 5, the S5/S8-U SGW
  F-TEID and the bearer QoS.
* Echo Requests of the PGW are answered. Its bearer requests are
  answered at once, without the scenario (see `Dedicated bearers`_);
  deleting the default bearer ends the session.
* The user plane is a TUN device and a forwarder thread. The UE address
  becomes a local address on the TUN device, and a rule routes
  everything sent from that address into it. The thread wraps packets
  from the device into GTP-U toward the PGW and unwraps what arrives on
  UDP 2152. The kernel's GTP driver is not used: it selects the tunnel
  by UE address alone and could not put RTP on a dedicated bearer. For
  every uplink packet the thread evaluates the uplink packet filters of
  the UE's dedicated bearers and uses the TEID of the bearer whose filter
  matches, or the default bearer's.
* IMS IPSec needs nothing special: the kernel applies the
  transport-mode ESP before the packet reaches the TUN device.


What a real visited network does differently
````````````````````````````````````````````

There is no S11, S1-U or NAS: MME and SGW are one, bearer requests are
answered without a radio leg, and ULI, serving network and equipment
identity are whatever the scenario says. No Modify Bearer Request is
sent. The EPS bearer id of a dedicated bearer, which an MME assigns, is
assigned by SIPp. A bearer's QoS (GBR, MBR, APN-AMBR) is not enforced on
uplink, and a Create Bearer Request is never refused for lack of
resources.


Testing against Open5GS
```````````````````````

For S6a point ``-s6a_peer`` at ``open5gs-hssd`` (freeDiameter, SCTP or
TCP 3868), or at PyHSS or a DRA in front of them. The peer has to accept
SIPp's Origin-Host; in Open5GS's freeDiameter configuration that is a
``ConnectPeer`` entry for it. The realm in ``-s6a_dest_realm`` is the
HSS's own. To
see a refusal, use a subscriber the HSS does not know (5001 on the AIR),
or one whose roaming it does not allow for the visited PLMN (5004 on the
ULR). PyHSS sends a Cancel Location on request, through its API
(``PUT /push/clr/<imsi>``).

The PGW side of Open5GS is ``open5gs-smfd`` (PGW-C) with
``open5gs-upfd`` (PGW-U); the SMF also needs its Gx peer
(``open5gs-pcrfd`` with MongoDB), or it answers "remote peer not
responding". In ``smf.yaml`` the ``gtpc`` address is what ``-s8_pgw``
points to; the subscriber must exist in the PCRF's database with the
APN. Run SIPp on a host the SMF and UPF can reach on its
``-s8_local_ip``.

In Wireshark, with a capture on SIPp's S8 interface:

``gtpv2``
    Create Session Request and Response. Check ``gtpv2.cause``, the two
    ``gtpv2.f_teid_interface_type`` values in the request (6 and 4) and
    in the response (7 and 5), ``gtpv2.pdn_addr_and_prefix.ipv4`` and
    the P-CSCF in the PCO.

``gtp && sip``
    SIP inside GTP-U. ``gtp.teid`` uplink is the PGW's user plane TEID
    from the response, downlink the one SIPp sent in the request. With
    ``-ipsec`` the protected messages show as ``gtp && esp``.

``gtpv2.message_type == 36 || gtpv2.message_type == 37``
    Delete Session at the end of the call.

``diameter.applicationId == 16777251``
    S6a (capture on the SCTP or TCP connection to the DRA or HSS). In the
    requests check ``diameter.Origin-Host``, ``diameter.Destination-Realm``,
    ``diameter.User-Name`` (the IMSI) and the Visited-PLMN-Id; in the
    Update Location Answer ``diameter.Result-Code`` or
    ``diameter.Experimental-Result-Code`` and the Subscription-Data with
    the APN-Configuration. ``diameter.cmd.code == 317`` shows a Cancel
    Location and SIPp's answer.

``gtpv2.message_type >= 95 && gtpv2.message_type <= 100``
    Create, Update and Delete Bearer. In the Create Bearer Request look
    at the bearer context: EBI 0, the TFT, the PGW's F-TEID (interface
    type 5) and the Bearer QoS with QCI 1. In SIPp's response: cause 16,
    the EBI it assigned, its own F-TEID (interface type 4, instance 2)
    and the PGW's F-TEID again (instance 3).

``gtp && rtp`` (or ``gtp && udp && !sip``)
    The media. Uplink ``gtp.teid`` has to be the TEID of the PGW's F-TEID
    in the Create Bearer Request, downlink the TEID SIPp answered with;
    SIP stays on the TEIDs of the Create Session exchange. Open5GS only
    creates the bearer when a PCRF with an Rx peer (the P-CSCF) asks for
    it; without one the call works, with media on the default bearer.


Limitations
```````````

* IPv4 PDN connections only.
* S6a: one peer, no failover; no Notify, no handling of the
  authentication vectors (there is no NAS), no TLS.
* Dedicated bearers come from the PGW only; SIPp does not ask for one
  (no Bearer Resource Command).
* SIP over UDP only (a P-CSCF that tries TCP toward the UE is refused
  and can fall back to UDP); ``rtp_stream`` actions are not tunnel-aware.
* PCAP play replays every UDP packet of the file, with ports shifted
  relative to the first one. For a voice bearer the media has to come
  from the port in the SDP, so use a file with one RTP direction only
  (``media/pcma_rtp.pcap``).
* One rule per UE in the kernel's policy routing: fine for hundreds of
  UEs, not meant for many thousands.


Troubleshooting
```````````````

``S8 <imsi>: no answer from the PGW``
    Nothing came back within T3 x (N3 + 1): wrong address, UDP 2123
    filtered, or the PGW does not accept SIPp's source address.

``Create Session rejected by the PGW, cause N``
    See TS 29.274 Table 8.4-1; the PGW's log names the reason.

Call answered, but ``carried 0 uplink`` on the voice bearer
    The RTP does not meet the bearer's uplink filters, which SIPp logs
    when the bearer is created: compare local port, remote address and
    remote port with the SDP. Typical cause: a media file with more than
    one flow.

Call answered, uplink counted, but ``0 downlink`` on both ends
    The home network does not carry the media between the two UE
    addresses; look at routing and forwarding at the PGW-U.

``refused the capabilities exchange`` / ``no Capabilities-Exchange-Answer``
    The Diameter peer does not know SIPp's Origin-Host or does not offer
    S6a: see its peer configuration, or set ``-s6a_origin_host`` and
    ``-s6a_origin_realm`` to names it accepts.

``S6a <imsi>: no answer from the HSS``
    The request went out but nothing came back in ``-s6a_timeout``: a DRA
    without a route for the Destination-Realm, or an HSS that cannot route
    its answer back.

``cannot connect to the Diameter peer ... over SCTP: Protocol not supported``
    The kernel has no SCTP (``modprobe sctp``, not possible inside an
    unprivileged container), or use ``-s6a_transport tcp``.

``cannot bind GTP-C`` / ``cannot bind the GTP-U socket``
    Another process (an SGW, an ePDG, a PGW) owns port 2123 or 2152 on
    that address.

``cannot open /dev/net/tun`` / ``cannot create the TUN device``
    In a container: ``--device /dev/net/tun --cap-add NET_ADMIN``.

To look at a running test::

    ip addr show dev sipps8_<pid>   # one /32 per UE
    ip rule                         # "from <UE> lookup <table>" per UE
