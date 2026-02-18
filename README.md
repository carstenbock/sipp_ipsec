<a href="https://scan.coverity.com/projects/5988">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/5988/badge.svg"/>
</a>

SIPp - a SIP protocol test tool
Copyright (C) 2003-2026 - The Authors

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program.  If not, see
[http://www.gnu.org/licenses/](http://www.gnu.org/licenses/).

# Documentation

See the `docs/` directory. It should also be available in html format at:
https://sipp.readthedocs.io/en/latest/

Build a local copy using: ``sphinx-build docs _build``

# Building

This is the SIPp package. Please refer to the
[webpage](http://sipp.sourceforge.net/) for details and documentation.

Normally, you should be able to build SIPp by using CMake:

```
cmake .
make
```

_The SIPp master branch (3.7.x) requires a modern C++17 compiler._

There are several optional flags to enable features (SIP-over-SCTP, media
playback from PCAP files, the GNU Scientific Libraries for random
distributions, and VoLTE IPSec):

```
cmake . -DUSE_SCTP=1 -DUSE_PCAP=1 -DUSE_GSL=1 -DUSE_IPSEC=1
```

## VoLTE IPSec support

To build with IPSec support for VoLTE IMS registration (3GPP TS 33.203),
pass `-DUSE_IPSEC=1` to cmake:

```
cmake . -DUSE_IPSEC=1
make
```

This requires the `libmnl` (minimalistic Netlink) development library:

```
# Debian/Ubuntu
sudo apt-get install libmnl-dev

# RHEL/Fedora
sudo dnf install libmnl-devel
```

When IPSec is enabled, SIPp can emulate a VoLTE UE by:

- Performing 3GPP AKA authentication and deriving CK/IK keys
- Creating IPSec Security Associations (ESP transport mode) via the
  Linux XFRM subsystem
- Negotiating security parameters using `Security-Client` /
  `Security-Server` / `Security-Verify` SIP headers (RFC 3329)
- Rebinding to protected ports for IPSec-encrypted SIP signaling

New command-line options:

| Option | Description | Default |
|--------|-------------|---------|
| `-ipsec` | Enable IPSec mode | disabled |
| `-ipsec_aalg` | Authentication algorithm (`hmac-sha-1-96`, `hmac-md5-96`) | `hmac-sha-1-96` |
| `-ipsec_ealg` | Encryption algorithm (`aes-cbc`, `des-ede3-cbc`, `null`) | `aes-cbc` |

New scenario keywords: `[security_client]`, `[security_verify]`

New scenario actions: `<ipsec_setup />`, `<ipsec_teardown />`

An example VoLTE registration scenario is provided in
`sipp_scenarios/volte_register.xml`.

**Note:** At runtime, SIPp needs root privileges or the `CAP_NET_ADMIN`
capability to create kernel IPSec Security Associations:

```
sudo ./sipp -sf sipp_scenarios/volte_register.xml -ipsec \
    -au 001010000000001 \
    -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
    -key aka_OP 0xCDC202D5123E20F62B6D676AC72CB318 \
    -key aka_AMF 0x8000 \
    192.168.1.1:5060
```

If your OPc is pre-computed, use `-key aka_OPc` instead of `-key aka_OP`:

```
sudo ./sipp -sf sipp_scenarios/volte_register.xml -ipsec \
    -au 001010000000001 \
    -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
    -key aka_OPc 0xE8ED289DEBA952E4283B54E88E6183CA \
    -key aka_AMF 0x8000 \
    192.168.1.1:5060
```

See `docs/ipsec.rst` for the full documentation.

## TLS key logging

To enable TLS key logging pass `-DTLS_KEY_LOGGING=1` to cmake.

TLS key logging records the TLS Session Keys to a key log file when the `SSLKEYLOGFILE` environment variable is set. It allows to decrypt SIPS traffic generated or received by SIPp using Wireshark. For more details see: https://wiki.wireshark.org/TLS

You need to compile with OpenSSL>=1.1.1 in order to use TLS key logging.

The TLS key log file format is described here: https://datatracker.ietf.org/doc/draft-ietf-tls-keylogfile/

_Please note the security considerations ("3. Security Considerations")!_

## Static builds

SIPp can be built into a single static binary, removing the need for
libraries to exist on the target system and maximising portability.

This is a [fairly complicated
process](https://medium.com/@neunhoef/static-binaries-for-a-c-application-f7c76f8041cf),
and for now, it only works on Alpine Linux.

To build a static binary, pass `-DBUILD_STATIC=1` to cmake.

An Alpine-based `Dockerfile` is provided, which can be used as a
build-environment.  Build with the following commands:

```
git submodule update --init
docker build -t sipp -f docker/Dockerfile --output=. --target=bin .
```

Special arguments can be passed with `--build-arg`:
* `FULL=1` - build all optional components.
* `DEBUG=1` - build with debug symbols.

## Debian-based docker build

SIPp can be built in a Debian-based docker container. Unlike the Alpine
build, this build is not static, and it supports wolfSSL.

To build a Debian-based docker container, run:
```
git submodule update --init
docker build -t sipp -f docker/Dockerfile.debian .
```

Special arguments can be passed with `--build-arg`:
* `FULL=1` - build all optional components.
* `WOLFSSL=1` - build with wolfSSL (only works without FULL).
* `DEBUG=1` - build with debug symbols.

## IPSec docker build (VoLTE)

A dedicated Dockerfile is provided for building SIPp with VoLTE IPSec
support. It is based on Debian 12, includes `libmnl` and `iproute2`,
and bundles the VoLTE scenario files under `/scenarios`.

To build:
```
git submodule update --init
docker build -t sipp-ipsec -f docker/Dockerfile.ipsec .
```

To run (requires `--cap-add=NET_ADMIN` for XFRM and `--net=host` for
real network interfaces):
```
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

If your OPc is pre-computed, use `-key aka_OPc` instead of `-key aka_OP`:

```
docker run --rm --cap-add=NET_ADMIN --net=host sipp-ipsec \
    -sf /scenarios/volte_register.xml -ipsec \
    -s 001010000000001 \
    -key domain ims.mnc001.mcc001.3gppnetwork.org \
    -au 001010000000001 \
    -key aka_K 0x465B5CE8B199B49FAA5F0A2EE238A6BC \
    -key aka_OPc 0xE8ED289DEBA952E4283B54E88E6183CA \
    -key aka_AMF 0x8000 \
    192.168.1.1:5060
```

Special arguments can be passed with `--build-arg`:
* `FULL=1` - also enable SCTP and TLS support.
* `DEBUG=1` - build with debug symbols.

# Support

I try and be responsive to issues raised on Github, and there's [a
reasonably active mailing
list](https://lists.sourceforge.net/lists/listinfo/sipp-users).

# Making a release

* Update CHANGES.md. Tag release. Do a build.
* Make `sipp.1` by calling:
    ```
    help2man --output=sipp.1 -v -v --no-info \
      --name='SIP testing tool and traffic generator' ./sipp
    ```
* Then:
    ```
    git ls-files -z | grep -zv '^\.\|gtest\|gmock\|version.h' | \
      tar --transform "s:^version.h:include/version.h:" \
          --transform "s:^:sipp-$VERSION/:" \
          --sort=name --mtime="@$(git log -1 --format=%ct)" \
          --owner=0 --group=0 --null --files-from=- \
          --numeric-owner -zcf sipp-$VERSION.tar.gz \
          sipp.1 version.h
    ```
* Upload to github as "binary". Note that github replaces tilde sign
  (for ~rcX) with a period.
* Create a static binary and upload this to github as well:
    ```
    docker build -t sipp -f docker/Dockerfile --output=. --target=bin .
    ```

# Contributing

SIPp is free software, under the terms of the GPL licence (see the
LICENCE.txt file for details). You can contribute to the development of
SIPp and use the standard Github fork/pull request method to integrate
your changes integrate your changes. If you make changes in SIPp,
*PLEASE* follow a few coding rules:

  - Please stay conformant with the current indentation style (4 spaces
    indent, standard Emacs-like indentation). Examples:

    ```
    if (condition) {        /* "{" even if only one instruction */
        f();                /* 4 space indents */
    } else {
        char* p = ptr;      /* C++-style pointer declaration placement */
        g(p);
    }
    ```

  - If possible, check that your changes can be compiled on:
      - Linux,
      - Cygwin,
      - Mac OS X,
      - FreeBSD.

Thanks,

  Rob Day <rkd@rkd.me.uk>
