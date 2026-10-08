VoWiFi (SWu) Support
====================

SIPp can emulate a UE on untrusted WLAN access: before any SIP is sent,
a call builds an IKEv2 tunnel to an ePDG (SWu, 3GPP TS 24.302 and
TS 33.402), authenticated with EAP-AKA' (RFC 5448) or EAP-AKA
(RFC 4187). The ePDG assigns the UE's IP address and names the P-CSCF;
the IMS registration, including its own IPSec (see :doc:`ipsec`), then
runs inside the tunnel.

The feature is built whenever SIPp is built with ``-DUSE_IPSEC=ON``
against OpenSSL (not wolfSSL). At runtime it needs root or
``CAP_NET_ADMIN``, as the tunnel is installed in the Linux kernel
(XFRM).


Usage
`````

Two scenario actions and one option:

``-swu_epdg <host>``
    The ePDG, as IPv4 address or host name.

``<swu_attach identity="..." k="..." opc="..." apn="ims"/>``
    Builds the tunnel. It must be the first step of a call, inside a
    ``<nop>``; the call waits there until the tunnel is up and fails if
    it cannot be built. All attributes may use keywords such as
    ``[field0]``. ``k`` and ``opc`` are 32 hex digits each; ``apn``
    defaults to ``ims``. ``pdn_type`` (``ipv4``, ``ipv6`` or ``ipv4v6``,
    default ``ipv4``) says which inner addresses to ask for, and
    ``sip_family`` (``ipv4`` or ``ipv6``) which of two SIP uses.

``<swu_detach/>``
    Sends the IKE Delete and waits for the answer. A call that ends
    without it deletes its tunnel as well, without waiting.

The identity is the NAI of TS 23.003 section 19.3.2. Its first digit
selects the EAP method at the AAA server:
``6<IMSI>@nai.epc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`` for EAP-AKA',
``0<IMSI>@...`` for EAP-AKA.

Once attached, these keywords are per call:

================  ====================================================
``[local_ip]``    the inner address assigned by the ePDG
``[media_ip]``    the same inner address
``[remote_ip]``   the P-CSCF named by the ePDG; the ``remote_host`` of
                  the command line is used only if it names none
================  ====================================================

``-t un`` (one UDP socket per call) is required, because every UE has
its own source address. ``-i`` is the outer (WLAN side) address.


Media
`````

RTP follows the call into its tunnel:

* ``play_pcap_audio`` / ``play_pcap_video`` / ``play_dtmf`` send from the
  call's inner address, the one ``[media_ip]`` wrote into the SDP, so the
  packets match the tunnel policy and leave through the SWu tunnel. Use
  ``[auto_media_port]`` to give every call its own port.
* With ``-rtp_echo`` and ``-swu_epdg`` the echo sockets listen on every
  local address instead of the process-wide media address, and each
  packet is echoed from the address it arrived on. All UEs can therefore
  advertise the same ``[media_port]``, each with its own inner address.

Scenarios: ``vowifi_uac.xml`` (MO call with PCAP audio) and
``vowifi_uas.xml`` (MT call with RTP echo), next to
``vowifi_register.xml``.

Example, with ``users.csv`` holding ``<imsi>;<K>;<OPc>`` per line::

    sudo ./sipp -sf sipp_scenarios/vowifi_register.xml \
        -swu_epdg 192.0.2.10 -ipsec -t un -inf users.csv \
        -key eap_prefix 6 \
        -key domain ims.mnc001.mcc001.3gppnetwork.org \
        -key nai_realm nai.epc.mnc001.mcc001.3gppnetwork.org \
        -key wlan_node_id 001122334455 \
        192.0.2.20:5060


How it works
````````````

* IKE_SA_INIT goes to UDP 500, everything after it to UDP 4500, from
  one socket and source port per UE. ESP is always UDP-encapsulated
  (RFC 3948), so any number of UEs can share one source address.
* One proposal is offered: AES-CBC-256, HMAC-SHA2-256-128,
  PRF-HMAC-SHA2-256, MODP-2048, for IKE and ESP alike.
* The UE offers ``EAP_ONLY_AUTHENTICATION`` (RFC 5998). The ePDG is
  authenticated by the AUTH payload computed from the EAP MSK, which is
  verified; a certificate it sends is not validated.
* The USIM is emulated with Milenage. The AUTN MAC is verified, the
  sequence number is not, so no resynchronisation is ever triggered.
* The inner address is added to ``lo``. A policy "everything from the
  inner address" sends traffic into the tunnel; the port-specific
  policies of the IMS IPSec carry a second, tunnel-mode template, which
  is what nests the IMS transport-mode ESP inside the tunnel ESP. With
  two separate policies the kernel would apply only the more specific
  one and send the IMS ESP out untunnelled.


IPv6 inner addresses
````````````````````

With ``pdn_type="ipv6"`` or ``"ipv4v6"`` the CFG_REQUEST asks for
INTERNAL_IP6_ADDRESS, INTERNAL_IP6_DNS and P_CSCF_IP6_ADDRESS, alone or
next to their IPv4 counterparts, and the traffic selectors cover IPv6.
An ePDG derives the PDN type it asks the PGW for from that. Both
families share the one pair of ESP SAs (IPv6 inside the IPv4 tunnel).

SIP runs over IPv6 if the ePDG named an IPv6 P-CSCF, over IPv4 otherwise;
``sip_family`` overrides the choice. A UE with only an IPv6 address needs
an IPv6 P-CSCF, from the ePDG or on the command line.

The host needs IPv6 for this, in two places SIPp takes care of where it
can: every inner IPv6 address gets a routing rule of its own (a host
without IPv6 connectivity has no route the IPsec policy could apply to),
and IPv6 is switched on for the interface with the outer address, where
decrypted packets count as received. The second needs a writable
``/proc/sys``: in Docker that is ``--privileged``, as the default bridge
network creates its interfaces with IPv6 disabled; SIPp warns when it
cannot do it.


Limitations
```````````

* The outer address (IKE and ESP to the ePDG) is IPv4. The inner address
  may be IPv4, IPv6 or both, see below.
* SIP over UDP only. The IMS IPSec SAs cover TCP too, so a P-CSCF that
  tries TCP toward the UE's protected server port is refused by the
  kernel and can fall back to UDP; SIPp does not accept such a connection.
* No rekeying: a ``CREATE_CHILD_SA`` from the ePDG is refused, so a
  call cannot outlive the SA lifetime. No MOBIKE, no NAT keepalives.
* The ``rtp_stream`` actions (SIPp's built-in RTP streaming) are not
  tunnel-aware; use PCAP play or ``-rtp_echo``.
* Large messages depend on the path: SIP goes over UDP, so an INVITE of
  a few kilobytes is IP-fragmented. An ePDG that fragments after
  encryption sends fragments of ESP-in-UDP packets, which a NAT in front
  of the SIPp host may drop (seen as an MT call that never rings).
* IP fragmentation is left to the kernel; large SIP messages are
  fragmented inside the tunnel.


Troubleshooting
```````````````

Attach failures are logged with ``-trace_err`` as
``SWu <identity>: <reason>``. Common ones:

``no response from ePDG``
    Nothing came back for IKE_SA_INIT: wrong address, or UDP 500/4500
    filtered.

``EAP-Failure from the AAA server``
    The subscriber is unknown to the HSS for this identity, or not
    allowed on the APN.

``AUTN does not verify``
    ``k`` / ``opc`` differ from what the HSS holds.

``IKE_AUTH rejected by the ePDG (notify N)``
    The ePDG refused after authentication, typically because the PGW
    rejected the session; see the ePDG log.

To check the kernel state of a running test::

    ip xfrm state          # 2 tunnel SAs + 4 IMS SAs per registered UE
    ip xfrm policy         # 2 tunnel + 4 IMS policies per UE
    ip addr show lo        # inner addresses
