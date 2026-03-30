VoLTE Scenario Reference
========================

This chapter documents the VoLTE SIPp scenario files shipped under
``sipp_scenarios/``. Each scenario simulates a VoLTE UE interacting
with an IMS core (P-CSCF) over IPSec-protected signaling.

All scenarios implement:

- **IMS Registration** with IPSec security mechanism agreement
  (3GPP TS 33.203 / RFC 3329)
- **Service-Route discovery** per `RFC 3608
  <https://datatracker.ietf.org/doc/html/rfc3608>`_
- **De-registration** (``Expires: 0``) with IPSec teardown


Registration and Service-Route
``````````````````````````````

Every VoLTE scenario begins with a full IMS registration cycle::

    UE                              P-CSCF / IMS
     |                                   |
     |--- REGISTER (unprotected) ------->|
     |    Security-Client                |
     |    Authorization (stub)           |
     |                                   |
     |<-- 401 Unauthorized --------------|
     |    WWW-Authenticate (AKA)         |
     |    Security-Server                |
     |                                   |
     |   [ipsec_setup: parse Security-   |
     |    Server, prepare XFRM params]   |
     |                                   |
     |--- REGISTER (over IPSec) -------->|
     |    Authorization (AKA digest)     |
     |    Security-Verify                |
     |                                   |
     |<-- 200 OK ------------------------|
     |    Service-Route: <sip:...;lr>    |
     |                                   |
     |   [Extract & store Service-Route] |

After the 200 OK, the ``Service-Route`` header value is extracted using
SIPp's ``ereg`` action::

    <recv response="200">
      <action>
        <ereg regexp=".*"
              search_in="hdr"
              header="Service-Route:"
              check_it="false"
              assign_to="service_route"/>
      </action>
    </recv>

The stored value is then injected as a preloaded ``Route`` header in all
subsequent originated requests::

    Route: [$service_route]

Per RFC 3608 Section 6.1, the UA preserves the order of Service-Route
values and uses them to direct requests through the home service proxy
chain (P-CSCF → S-CSCF).


Scenario Catalog
````````````````

volte_register.xml
------------------

**Purpose:** Basic IMS registration and de-registration test.

**Flow:** REGISTER → 401 → IPSec setup → REGISTER → 200 OK
(Service-Route extracted) → pause → de-REGISTER → 200 OK → IPSec
teardown.

**Usage:**

.. code-block:: bash

    sudo ./sipp -sf sipp_scenarios/volte_register.xml -ipsec \
        -s 001010000000001 \
        -key domain ims.mnc001.mcc001.3gppnetwork.org \
        -au 001010000000001 \
        -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
        -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
        -key aka_AMF 0x8000 \
        192.168.1.1:5060

If your OPc is pre-computed, use ``-key aka_OPc`` instead of
``-key aka_OP``.


volte_uac_template.xml
----------------------

**Purpose:** Mobile Originated (MO) VoLTE call — full flow from
registration through media to de-registration.

**Flow:** REGISTER → 401 → IPSec → REGISTER → 200 OK → INVITE
(with Service-Route as Route) → 183/PRACK or 180 → 200 OK → ACK →
media (``play_pcap_audio``) → BYE → de-REGISTER → IPSec teardown.

**Placeholders** (replaced by the scenario generator):

================= ================================================
Placeholder       Description
================= ================================================
``__DOMAIN__``    IMS home domain
``__TARGET_URI__``  Called party URI (``tel:`` or ``sip:``)
``__MSISDN__``    Calling party MSISDN (public user identity)
``__SDP_OFFER__`` Codec-specific SDP body
``__PCAP_FILE__`` Path to RTP PCAP for ``play_pcap_audio``
``__CALL_DURATION_MS__``  Active call duration in milliseconds
``__AKA_K__``     AKA K key (hex)
``__AKA_OPC__``   AKA OPc key (hex, pre-computed)
``__AKA_AMF__``   AKA AMF (hex)
================= ================================================

The INVITE, PRACK, ACK, and BYE messages all include
``Route: [$service_route]`` derived from the REGISTER 200 OK.


volte_uas_template.xml
----------------------

**Purpose:** Mobile Terminated (MT) VoLTE call — the called-side UE.

**Flow:** REGISTER → 401 → IPSec → REGISTER → 200 OK → wait for
INVITE → 100 Trying → 180 Ringing → 200 OK (with SDP answer) → ACK →
RTP echo → BYE → 200 OK → de-REGISTER → IPSec teardown.

**Usage:**

.. code-block:: bash

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

RTP is handled with ``rtp_echo`` (loops back received RTP), validating
the media path without requiring a PCAP file.


volte_mixed_load.xml
--------------------

**Purpose:** CSV-driven composite load scenario for concurrent call
generation.

**Flow:** REGISTER → 401 → IPSec → REGISTER → 200 OK → INVITE (from
CSV parameters, with Service-Route as Route) → media → BYE →
de-REGISTER → IPSec teardown.

**CSV format** (no header row, fields 0–7):

.. code-block:: text

    scenario,target_uri,domain,calling_msisdn,ue_codec_pt,gw_codec_pt,call_duration_ms,imsi

**Example row:**

.. code-block:: text

    ue_to_gw,tel:+4989200011251,ims.mnc001.mcc001.3gppnetwork.org,494034927217,116,9,8000,001019999900001

**Usage:**

.. code-block:: bash

    sudo ./sipp -sf sipp_scenarios/volte_mixed_load.xml -ipsec \
        -inf mixed_load.csv \
        -s 001010000000001 \
        -au 001010000000001 \
        -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
        -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
        -key aka_AMF 0x8000 \
        -l 100 -r 5 \
        192.168.1.1:5060


volte_reregister_cycle.xml
--------------------------

**Purpose:** Registration refresh stress test — rapid REGISTER/refresh
cycles for P-CSCF and S-CSCF load testing.

**Flow:** REGISTER → 401 → IPSec → REGISTER → 200 OK (Service-Route
extracted) → pause → re-REGISTER (refresh, optional 401) → 200 OK
(Service-Route updated) → de-REGISTER → IPSec teardown.

The Service-Route is re-extracted on every 200 OK to handle the case
where the registrar updates the route vector on refresh.

**Usage:**

.. code-block:: bash

    sudo ./sipp -sf sipp_scenarios/volte_reregister_cycle.xml -ipsec \
        -s 001010000000001 \
        -key domain ims.mnc001.mcc001.3gppnetwork.org \
        -key expires 600 \
        -key refresh_count 5 \
        -au 001010000000001 \
        -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
        -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
        -key aka_AMF 0x8000 \
        -l 50 -r 10 \
        192.168.1.1:5060


volte_routing_probe.xml
-----------------------

**Purpose:** SBC/IMS routing validation — sends an INVITE to verify
that a signaling path exists for a given target number, without
establishing a media session.

**Flow:** REGISTER → 401 → IPSec → REGISTER → 200 OK → INVITE (with
Service-Route as Route) → check response → CANCEL/ACK/BYE as
appropriate → de-REGISTER → IPSec teardown.

**Expected outcomes:**

============  ======  ==========================================
Response      Result  Interpretation
============  ======  ==========================================
1xx / 2xx     PASS    Route exists and is reachable
486 / 480     PASS    Target busy/unavailable — signaling works
404           FAIL    No matching route
403 / 503     FAIL    Route blocked or unavailable
============  ======  ==========================================

**Usage:**

.. code-block:: bash

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


Docker Usage
````````````

All scenarios can be run from the ``sipp-ipsec`` Docker image. The
container requires ``--cap-add=NET_ADMIN`` for XFRM SA management and
``--net=host`` for real network interfaces:

.. code-block:: bash

    docker run --rm --cap-add=NET_ADMIN --net=host sipp-ipsec \
        -sf /scenarios/volte_register.xml -ipsec \
        -s 001010000000001 \
        -key domain ims.mnc001.mcc001.3gppnetwork.org \
        -au 001010000000001 \
        -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
        -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
        -key aka_AMF 0x8000 \
        192.168.1.1:5060

Scenario files are mounted at ``/scenarios/`` inside the container.


Troubleshooting
```````````````

**"Operation not permitted" on startup**
    SIPp needs ``CAP_NET_ADMIN`` to create XFRM SAs. Run with ``sudo``
    or use ``--cap-add=NET_ADMIN`` in Docker.

**401 loop (never gets 200 OK)**
    Check AKA credentials. Verify that ``aka_K``, ``aka_OP``/``aka_OPc``,
    and ``aka_AMF`` match the HSS configuration. Use ``-key aka_OPc``
    if your OPc is pre-computed.

**INVITE rejected with 403**
    The Service-Route may be missing or malformed. Enable SIPp trace
    (``-trace_msg``) and verify that the ``Route`` header in the INVITE
    matches the ``Service-Route`` from the REGISTER 200 OK.

**No media / one-way audio**
    Ensure RTP ports are reachable. For UAC scenarios, verify the PCAP
    file path. For UAS scenarios, confirm ``rtp_echo`` is active.

**IPSec SA not created**
    Check ``ip xfrm state`` and ``ip xfrm policy`` output. Verify that
    the ``Security-Server`` header in the 401 response contains valid
    SPI, port, and algorithm parameters.
