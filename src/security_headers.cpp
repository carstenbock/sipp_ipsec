/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *  SIP Security headers per RFC 3329 and 3GPP TS 33.203.
 */

#ifdef USE_IPSEC

#include "security_headers.hpp"
#include "sipp.hpp"

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>

/**
 * Skip whitespace in a string.
 */
static const char *skip_ws(const char *s)
{
    while (*s && isspace((unsigned char)*s))
        s++;
    return s;
}

/**
 * Extract a named parameter value from a header.
 * Looks for "name=value" where value may be quoted or unquoted.
 * Returns pointer to start of value, sets *end to end of value.
 */
static const char *find_param(const char *header, const char *name, const char **end)
{
    const char *p = header;
    size_t nlen = strlen(name);

    while ((p = strcasestr(p, name)) != nullptr) {
        /* Verify it's a parameter boundary (preceded by ; or start) */
        if (p > header) {
            char prev = *(p - 1);
            if (prev != ';' && prev != ',' && !isspace((unsigned char)prev)) {
                p += nlen;
                continue;
            }
        }
        p += nlen;
        p = skip_ws(p);
        if (*p != '=') continue;
        p++;
        p = skip_ws(p);

        if (*p == '"') {
            p++;
            *end = strchr(p, '"');
            if (!*end) *end = p + strlen(p);
            return p;
        } else {
            *end = p;
            while (**end && **end != ';' && **end != ',' && !isspace((unsigned char)**end))
                (*end)++;
            return p;
        }
    }
    return nullptr;
}

static uint32_t extract_uint32(const char *header, const char *name)
{
    const char *end;
    const char *val = find_param(header, name, &end);
    if (!val) return 0;

    char tmp[32];
    size_t len = (size_t)(end - val);
    if (len >= sizeof(tmp)) len = sizeof(tmp) - 1;
    memcpy(tmp, val, len);
    tmp[len] = '\0';
    return (uint32_t)strtoul(tmp, nullptr, 10);
}

static uint16_t extract_uint16(const char *header, const char *name)
{
    return (uint16_t)extract_uint32(header, name);
}

static void extract_string(const char *header, const char *name, char *out, size_t out_len)
{
    const char *end;
    const char *val = find_param(header, name, &end);
    if (!val) {
        out[0] = '\0';
        return;
    }
    size_t len = (size_t)(end - val);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, val, len);
    out[len] = '\0';
}

/*
 * All algorithm combinations offered in Security-Client per 3GPP TS 33.203.
 * Real UEs (e.g. iOS) list every supported {aalg, ealg} pair so the P-CSCF
 * can pick its preferred one.  The CLI-preferred pair is emitted first.
 */
static const char *all_aalgs[] = { "hmac-md5-96", "hmac-sha-1-96" };
static const char *all_ealgs[] = { "aes-cbc", "null" };
#define NUM_AALGS (sizeof(all_aalgs) / sizeof(all_aalgs[0]))
#define NUM_EALGS (sizeof(all_ealgs) / sizeof(all_ealgs[0]))

int build_security_client_header(const IPSecParams &params,
                                 char *result, size_t result_len)
{
    char *p = result;
    size_t left = result_len;
    bool first = true;

    /*
     * Pass 1: emit the CLI-preferred combination first.
     * Pass 2: emit all remaining combinations.
     */
    for (int pass = 0; pass < 2; pass++) {
        for (size_t ai = 0; ai < NUM_AALGS; ai++) {
            for (size_t ei = 0; ei < NUM_EALGS; ei++) {
                bool is_preferred =
                    strcasecmp(all_aalgs[ai], params.algos.aalg) == 0 &&
                    strcasecmp(all_ealgs[ei], params.algos.ealg) == 0;

                if ((pass == 0) != is_preferred)
                    continue;

                int n = snprintf(p, left, "%sipsec-3gpp;alg=%s;ealg=%s;"
                    "mod=trans;port-c=%u;port-s=%u;prot=esp;"
                    "spi-c=%u;spi-s=%u",
                    first ? "" : ",",
                    all_aalgs[ai], all_ealgs[ei],
                    params.port_uc, params.port_us,
                    params.spi_uc, params.spi_us);

                if (n < 0 || (size_t)n >= left) {
                    WARNING("Security-Client header too long");
                    return 0;
                }
                p += n;
                left -= (size_t)n;
                first = false;
            }
        }
    }

    return (int)(p - result);
}

int parse_security_server_header(const char *header, IPSecParams &params)
{
    if (!header || !*header) {
        WARNING("Empty Security-Server header");
        return -1;
    }

    /* Verify this is ipsec-3gpp mechanism */
    if (strcasestr(header, "ipsec-3gpp") == nullptr) {
        WARNING("Security-Server does not contain ipsec-3gpp mechanism");
        return -1;
    }

    params.spi_pc = extract_uint32(header, "spi-c");
    params.spi_ps = extract_uint32(header, "spi-s");
    params.port_pc = extract_uint16(header, "port-c");
    params.port_ps = extract_uint16(header, "port-s");

    /* Extract algorithms if provided (otherwise keep defaults) */
    char alg_buf[64];
    extract_string(header, "alg", alg_buf, sizeof(alg_buf));
    if (alg_buf[0])
        snprintf(params.algos.aalg, sizeof(params.algos.aalg), "%s", alg_buf);

    extract_string(header, "ealg", alg_buf, sizeof(alg_buf));
    if (alg_buf[0])
        snprintf(params.algos.ealg, sizeof(params.algos.ealg), "%s", alg_buf);

    if (params.spi_pc == 0 || params.spi_ps == 0) {
        WARNING("Security-Server missing SPI values (spi-c=%u, spi-s=%u)",
                params.spi_pc, params.spi_ps);
        return -1;
    }

    if (params.port_pc == 0 || params.port_ps == 0) {
        WARNING("Security-Server missing port values (port-c=%u, port-s=%u)",
                params.port_pc, params.port_ps);
        return -1;
    }

    LOG_MSG("Parsed Security-Server: spi-c=%u, spi-s=%u, port-c=%u, port-s=%u, alg=%s, ealg=%s\n",
            params.spi_pc, params.spi_ps, params.port_pc, params.port_ps,
            params.algos.aalg, params.algos.ealg);

    return 0;
}

int build_security_verify_header(const char *security_server_value,
                                 char *result, size_t result_len)
{
    if (!security_server_value || !*security_server_value) {
        WARNING("No Security-Server value to verify");
        return 0;
    }

    /* Security-Verify is an exact copy of the Security-Server value */
    int written = snprintf(result, result_len, "%s", security_server_value);
    if (written < 0 || (size_t)written >= result_len) {
        WARNING("Security-Verify header too long");
        return 0;
    }
    return written;
}

#endif /* USE_IPSEC */
