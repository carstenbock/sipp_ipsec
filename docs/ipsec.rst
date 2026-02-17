VoLTE IPSec Support
===================

SIPp includes optional support for IPSec as used in VoLTE (Voice over
LTE) IMS registration, per 3GPP TS 33.203. When enabled, SIPp can
emulate a VoLTE UE (User Equipment) by performing AKA authentication,
deriving the Cipher Key (CK) and Integrity Key (IK), and establishing
IPSec Security Associations with the P-CSCF using the Linux kernel
XFRM subsystem.

This feature requires building SIPp with ``-DUSE_IPSEC=ON`` and the
``libmnl`` library. At runtime, root privileges or the
``CAP_NET_ADMIN`` capability are required to create kernel-level
Security Associations and Security Policies.


Overview
````````

In VoLTE, the UE and P-CSCF negotiate IPSec protection during IMS
registration using the Security Mechanism Agreement procedure
(RFC 3329) with the ``ipsec-3gpp`` mechanism. The registration flow
is:

1. **Initial REGISTER (unprotected):** The UE sends a REGISTER with a
   ``Security-Client`` header advertising its SPIs, ports, and
   preferred algorithms.

2. **401 Unauthorized:** The P-CSCF responds with a 401 containing
   a ``WWW-Authenticate`` header (AKA challenge) and a
   ``Security-Server`` header with the P-CSCF's SPIs and ports.

3. **AKA + IPSec setup:** The UE runs the Milenage AKA algorithm to
   derive RES (for the SIP Digest response), CK (for IPSec
   encryption), and IK (for IPSec integrity). It then creates 4
   IPSec Security Associations in the kernel.

4. **Re-REGISTER (IPSec-protected):** The UE sends a second REGISTER
   over the now-protected path, including ``Authorization``,
   ``Security-Client``, and ``Security-Verify`` headers.

5. **200 OK (IPSec-protected):** The P-CSCF confirms the registration.
   All subsequent SIP signaling uses IPSec.

SIPp automates this entire flow using the ``-ipsec`` command-line
flag, scenario keywords (``[security_client]``, ``[security_verify]``),
and the ``<ipsec_setup/>`` / ``<ipsec_teardown/>`` scenario actions.


Command-line options
````````````````````

``-ipsec``
    Enable IPSec mode for VoLTE IMS registration. When enabled, SIPp
    will set up IPSec Security Associations using CK/IK derived from
    AKA authentication. Requires root or ``CAP_NET_ADMIN``.

``-ipsec_aalg <algorithm>``
    Set the IPSec authentication (integrity) algorithm. Default is
    ``hmac-sha-1-96``. Supported values:

    - ``hmac-sha-1-96`` (default, uses IK as key)
    - ``hmac-md5-96``

``-ipsec_ealg <algorithm>``
    Set the IPSec encryption algorithm. Default is ``aes-cbc``.
    Supported values:

    - ``aes-cbc`` (default, uses CK as 128-bit key)
    - ``des-ede3-cbc``
    - ``null`` (no encryption, integrity only)


Scenario keywords
`````````````````

Two new keywords are available when SIPp is built with IPSec support:

``[security_client]``
    Expands to the value of the ``Security-Client`` header for the
    current call. Contains the ``ipsec-3gpp`` mechanism with the UE's
    locally allocated SPIs, ports, and negotiated algorithms. Example
    expansion::

        ipsec-3gpp; alg=hmac-sha-1-96; ealg=aes-cbc; spi-c=12345; spi-s=12346; port-c=5060; port-s=5061

    This keyword should be used in the ``Security-Client:`` header of
    both the initial and re-REGISTER messages.

``[security_verify]``
    Expands to the cached value of the ``Security-Server`` header
    received from the P-CSCF in the 401 response. Per RFC 3329, the
    ``Security-Verify`` header in the re-REGISTER must be an exact
    echo of the ``Security-Server`` value.


Scenario actions
````````````````

Two new scenario actions are available inside ``<action>`` blocks:

``<ipsec_setup />``
    Triggers IPSec Security Association setup. This action should be
    placed in the ``<action>`` block of the ``<recv response="401">``
    step. It performs the following:

    1. Extracts the ``Security-Server`` header from the 401 message
    2. Parses the P-CSCF's SPIs and port numbers
    3. Creates 4 XFRM Security Associations (ESP transport mode)
    4. Creates 4 XFRM Security Policies
    5. Rebinds the call's socket to the protected client port

    After this action, all subsequent SIP messages for this call are
    sent over the IPSec-protected path.

``<ipsec_teardown />``
    Removes the IPSec Security Associations and Policies from the
    kernel. This should be called when de-registering or when the
    call ends. If not called explicitly, SAs are automatically cleaned
    up when the call is destroyed.


Security Associations
`````````````````````

SIPp creates 4 ESP (Encapsulating Security Payload) Security
Associations in transport mode:

+----+---------------------------+-----------------------------+-----------+
| SA | Direction                 | Ports                       | SPI       |
+====+===========================+=============================+===========+
| 1  | UE:port_c -> P-CSCF:port_s| Outbound (UE sends)        | spi_ps    |
+----+---------------------------+-----------------------------+-----------+
| 2  | P-CSCF:port_s -> UE:port_c| Inbound (responses)         | spi_uc    |
+----+---------------------------+-----------------------------+-----------+
| 3  | P-CSCF:port_c -> UE:port_s| Inbound (P-CSCF requests)   | spi_us    |
+----+---------------------------+-----------------------------+-----------+
| 4  | UE:port_s -> P-CSCF:port_c| Outbound (UE responses)     | spi_pc    |
+----+---------------------------+-----------------------------+-----------+

Where:

- ``spi_uc``, ``spi_us`` are generated locally by SIPp (UE side)
- ``spi_pc``, ``spi_ps`` are received from the P-CSCF via the
  ``Security-Server`` header
- ``port_c`` = protected client port (SIPp sends from here)
- ``port_s`` = protected server port (SIPp receives here)

The integrity key is derived from IK (Milenage f4) and the encryption
key from CK (Milenage f3), both computed during AKA authentication.


Example scenario
````````````````

The following shows a VoLTE IMS registration scenario with IPSec. A
complete example is provided in
``sipp_scenarios/volte_register.xml``.

::

    <scenario name="VoLTE Registration">

      <!-- Step 1: Initial REGISTER (unprotected) -->
      <send retrans="500">
        <![CDATA[
          REGISTER sip:[remote_ip] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
          From: <sip:[service]@ims.example.com>;tag=[call_number]
          To: <sip:[service]@ims.example.com>
          Call-ID: [call_id]
          CSeq: 1 REGISTER
          Contact: <sip:[service]@[local_ip]:[local_port]>
          Supported: sec-agree
          Require: sec-agree
          Proxy-Require: sec-agree
          Security-Client: [security_client]
          Max-Forwards: 70
          Expires: 600000
          Content-Length: 0
        ]]>
      </send>

      <!-- Step 2: Receive 401 + set up IPSec -->
      <recv response="401" auth="true">
        <action>
          <ipsec_setup />
        </action>
      </recv>

      <!-- Step 3: Re-REGISTER over IPSec -->
      <send retrans="500">
        <![CDATA[
          REGISTER sip:[remote_ip] SIP/2.0
          Via: SIP/2.0/[transport] [local_ip]:[local_port];branch=[branch]
          From: <sip:[service]@ims.example.com>;tag=[call_number]
          To: <sip:[service]@ims.example.com>
          Call-ID: [call_id]
          CSeq: 2 REGISTER
          Contact: <sip:[service]@[local_ip]:[local_port]>
          [authentication username=[service]@ims.example.com]
          Supported: sec-agree
          Require: sec-agree
          Proxy-Require: sec-agree
          Security-Client: [security_client]
          Security-Verify: [security_verify]
          Max-Forwards: 70
          Expires: 600000
          Content-Length: 0
        ]]>
      </send>

      <!-- Step 4: Receive 200 OK -->
      <recv response="200" />

    </scenario>


Running the example::

    sudo ./sipp -sf sipp_scenarios/volte_register.xml \
        -ipsec \
        -au 001010000000001 \
        -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
        -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
        -key aka_AMF 0x8000 \
        192.168.1.1:5060


.. note::
   The AKA keys (K, OP, AMF) must match the values stored in the HSS
   for the subscriber being tested. These are typically provisioned
   when setting up the test environment.


Future: VoWiFi support
``````````````````````

The IPSec architecture is designed to accommodate future VoWiFi
(Voice over WiFi) support. VoWiFi uses IKEv2 + IPSec tunnel mode
to an ePDG (evolved Packet Data Gateway), with EAP-AKA' authentication.
The XFRM netlink layer already supports tunnel mode, so extending
SIPp for VoWiFi would involve adding an IKEv2 state machine on top
of the existing IPSec infrastructure.


Troubleshooting
```````````````

Permission denied when creating SAs
    SIPp needs ``CAP_NET_ADMIN`` or root to create XFRM Security
    Associations. Run with ``sudo`` or set the capability::

        sudo setcap cap_net_admin+ep ./sipp

Security-Server header not found
    Ensure the P-CSCF is configured to send a ``Security-Server``
    header in the 401 response. This is mandatory for IMS IPSec.

IPSec SAs not visible in ``ip xfrm state``
    Verify that the XFRM subsystem is enabled in your kernel
    (``CONFIG_XFRM=y``). Check ``dmesg`` for any XFRM errors.

Traffic not being encrypted
    Use ``tcpdump`` or Wireshark to verify ESP packets (protocol 50)
    are being sent instead of plain UDP/TCP. Verify that the Security
    Policies are in place with ``ip xfrm policy``.
