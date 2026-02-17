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
 *  XFRM Netlink interface for IPSec SA/SP management via libmnl.
 *  Used for VoLTE IPSec (3GPP TS 33.203) Security Association setup.
 */

#ifdef USE_IPSEC

#include "xfrm_netlink.hpp"
#include "sipp.hpp"

#include <cstring>
#include <cerrno>
#include <cstdlib>

#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/xfrm.h>
#include <linux/netlink.h>
#include <libmnl/libmnl.h>

/* Use a fixed buffer size to avoid VLA in C++ */
#define XFRM_BUF_SIZE 8192

static struct mnl_socket *xfrm_nl = nullptr;
static uint32_t xfrm_seq = 0;
static uint32_t xfrm_portid = 0;

static int parse_ip(const char *ip_str, xfrm_address_t *addr, uint16_t *family)
{
    if (inet_pton(AF_INET, ip_str, &addr->a4) == 1) {
        *family = AF_INET;
        return 0;
    }
    if (inet_pton(AF_INET6, ip_str, &addr->a6) == 1) {
        *family = AF_INET6;
        return 0;
    }
    return -1;
}

static int xfrm_send_and_recv(struct nlmsghdr *nlh)
{
    char buf[XFRM_BUF_SIZE];

    if (mnl_socket_sendto(xfrm_nl, nlh, nlh->nlmsg_len) < 0) {
        WARNING("xfrm netlink send failed: %s", strerror(errno));
        return -1;
    }

    ssize_t ret = mnl_socket_recvfrom(xfrm_nl, buf, sizeof(buf));
    if (ret < 0) {
        WARNING("xfrm netlink recv failed: %s", strerror(errno));
        return -1;
    }

    ret = mnl_cb_run(buf, ret, xfrm_seq, xfrm_portid, nullptr, nullptr);
    if (ret < 0) {
        WARNING("xfrm netlink response error: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int xfrm_init(void)
{
    xfrm_nl = mnl_socket_open(NETLINK_XFRM);
    if (!xfrm_nl) {
        WARNING("Failed to open XFRM netlink socket: %s", strerror(errno));
        return -1;
    }

    if (mnl_socket_bind(xfrm_nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        WARNING("Failed to bind XFRM netlink socket: %s", strerror(errno));
        mnl_socket_close(xfrm_nl);
        xfrm_nl = nullptr;
        return -1;
    }

    xfrm_portid = mnl_socket_get_portid(xfrm_nl);
    return 0;
}

void xfrm_cleanup(void)
{
    if (xfrm_nl) {
        mnl_socket_close(xfrm_nl);
        xfrm_nl = nullptr;
    }
}

int xfrm_add_sa(const char *src_ip, const char *dst_ip,
                uint32_t spi, uint16_t src_port, uint16_t dst_port,
                int proto,
                const char *aalg_name, const unsigned char *aalg_key, int aalg_bits,
                const char *ealg_name, const unsigned char *ealg_key, int ealg_bits)
{
    char buf[XFRM_BUF_SIZE];
    struct nlmsghdr *nlh;
    struct xfrm_usersa_info *sa;
    xfrm_address_t src_addr, dst_addr;
    uint16_t src_family, dst_family;

    if (!xfrm_nl) {
        WARNING("XFRM netlink not initialized");
        return -1;
    }

    if (parse_ip(src_ip, &src_addr, &src_family) < 0) {
        WARNING("Invalid source IP: %s", src_ip);
        return -1;
    }
    if (parse_ip(dst_ip, &dst_addr, &dst_family) < 0) {
        WARNING("Invalid destination IP: %s", dst_ip);
        return -1;
    }
    if (src_family != dst_family) {
        WARNING("Source and destination address families must match");
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = XFRM_MSG_NEWSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++xfrm_seq;

    sa = (struct xfrm_usersa_info *)mnl_nlmsg_put_extra_header(nlh, sizeof(*sa));

    /* SA selector: match traffic by ports and protocol */
    sa->sel.family = src_family;
    sa->sel.saddr = src_addr;
    sa->sel.daddr = dst_addr;
    sa->sel.sport = htons(src_port);
    sa->sel.dport = htons(dst_port);
    sa->sel.sport_mask = src_port ? 0xFFFF : 0;
    sa->sel.dport_mask = dst_port ? 0xFFFF : 0;
    sa->sel.proto = proto;
    sa->sel.prefixlen_s = (src_family == AF_INET) ? 32 : 128;
    sa->sel.prefixlen_d = (src_family == AF_INET) ? 32 : 128;

    /* SA identification */
    sa->id.daddr = dst_addr;
    sa->id.spi = htonl(spi);
    sa->id.proto = IPPROTO_ESP;

    sa->saddr = src_addr;
    sa->family = src_family;

    /* ESP transport mode */
    sa->mode = XFRM_MODE_TRANSPORT;
    sa->replay_window = 32;
    sa->reqid = spi;

    /* Soft/hard lifetime: no expiry (infinite) */
    sa->lft.soft_byte_limit = XFRM_INF;
    sa->lft.hard_byte_limit = XFRM_INF;
    sa->lft.soft_packet_limit = XFRM_INF;
    sa->lft.hard_packet_limit = XFRM_INF;

    /* Authentication algorithm attribute */
    if (aalg_name && aalg_key) {
        int key_bytes = (aalg_bits + 7) / 8;
        size_t attr_len = sizeof(struct xfrm_algo) + key_bytes;

        /* Build the attribute manually for proper layout */
        struct nlattr *attr = (struct nlattr *)((char *)nlh + MNL_ALIGN(nlh->nlmsg_len));
        attr->nla_type = XFRMA_ALG_AUTH;
        attr->nla_len = MNL_ALIGN(sizeof(struct nlattr) + attr_len);

        struct xfrm_algo *auth_algo = (struct xfrm_algo *)((char *)attr + sizeof(struct nlattr));
        memset(auth_algo, 0, attr_len);
        strncpy(auth_algo->alg_name, aalg_name, sizeof(auth_algo->alg_name) - 1);
        auth_algo->alg_key_len = aalg_bits;

        /* Copy IK (16 bytes) and zero-pad to HMAC-SHA1 key size (20 bytes) if needed */
        memcpy(auth_algo->alg_key, aalg_key, (aalg_bits <= 128) ? 16 : key_bytes);

        nlh->nlmsg_len += MNL_ALIGN(attr->nla_len);
    }

    /* Encryption algorithm attribute */
    if (ealg_name && ealg_key && ealg_bits > 0) {
        int key_bytes = (ealg_bits + 7) / 8;
        size_t attr_len = sizeof(struct xfrm_algo) + key_bytes;

        struct nlattr *attr = (struct nlattr *)((char *)nlh + MNL_ALIGN(nlh->nlmsg_len));
        attr->nla_type = XFRMA_ALG_CRYPT;
        attr->nla_len = MNL_ALIGN(sizeof(struct nlattr) + attr_len);

        struct xfrm_algo *enc_algo = (struct xfrm_algo *)((char *)attr + sizeof(struct nlattr));
        memset(enc_algo, 0, attr_len);
        strncpy(enc_algo->alg_name, ealg_name, sizeof(enc_algo->alg_name) - 1);
        enc_algo->alg_key_len = ealg_bits;
        memcpy(enc_algo->alg_key, ealg_key, key_bytes);

        nlh->nlmsg_len += MNL_ALIGN(attr->nla_len);
    } else if (ealg_name) {
        /* Null cipher: no key needed */
        size_t attr_len = sizeof(struct xfrm_algo);

        struct nlattr *attr = (struct nlattr *)((char *)nlh + MNL_ALIGN(nlh->nlmsg_len));
        attr->nla_type = XFRMA_ALG_CRYPT;
        attr->nla_len = MNL_ALIGN(sizeof(struct nlattr) + attr_len);

        struct xfrm_algo *enc_algo = (struct xfrm_algo *)((char *)attr + sizeof(struct nlattr));
        memset(enc_algo, 0, attr_len);
        strncpy(enc_algo->alg_name, ealg_name, sizeof(enc_algo->alg_name) - 1);
        enc_algo->alg_key_len = 0;

        nlh->nlmsg_len += MNL_ALIGN(attr->nla_len);
    }

    return xfrm_send_and_recv(nlh);
}

int xfrm_del_sa(const char *src_ip, const char *dst_ip,
                uint32_t spi, int /* proto */)
{
    char buf[XFRM_BUF_SIZE];
    struct nlmsghdr *nlh;
    struct xfrm_usersa_id *sa_id;
    xfrm_address_t dst_addr;
    uint16_t dst_family;

    if (!xfrm_nl) {
        WARNING("XFRM netlink not initialized");
        return -1;
    }

    if (parse_ip(dst_ip, &dst_addr, &dst_family) < 0) {
        WARNING("Invalid destination IP: %s", dst_ip);
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = XFRM_MSG_DELSA;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++xfrm_seq;

    sa_id = (struct xfrm_usersa_id *)mnl_nlmsg_put_extra_header(nlh, sizeof(*sa_id));
    sa_id->daddr = dst_addr;
    sa_id->spi = htonl(spi);
    sa_id->proto = IPPROTO_ESP;
    sa_id->family = dst_family;

    /* Add source address attribute */
    xfrm_address_t src_addr;
    uint16_t src_family;
    if (parse_ip(src_ip, &src_addr, &src_family) == 0) {
        mnl_attr_put(nlh, XFRMA_SRCADDR, sizeof(src_addr), &src_addr);
    }

    return xfrm_send_and_recv(nlh);
}

int xfrm_add_policy(const char *src_ip, const char *dst_ip,
                    uint16_t src_port, uint16_t dst_port, int proto,
                    int dir, uint32_t spi,
                    const char *tmpl_src, const char *tmpl_dst)
{
    char buf[XFRM_BUF_SIZE];
    struct nlmsghdr *nlh;
    struct xfrm_userpolicy_info *pol;
    xfrm_address_t src_addr, dst_addr;
    uint16_t src_family, dst_family;

    if (!xfrm_nl) {
        WARNING("XFRM netlink not initialized");
        return -1;
    }

    if (parse_ip(src_ip, &src_addr, &src_family) < 0) {
        WARNING("Invalid source IP: %s", src_ip);
        return -1;
    }
    if (parse_ip(dst_ip, &dst_addr, &dst_family) < 0) {
        WARNING("Invalid destination IP: %s", dst_ip);
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = XFRM_MSG_NEWPOLICY;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = ++xfrm_seq;

    pol = (struct xfrm_userpolicy_info *)mnl_nlmsg_put_extra_header(nlh, sizeof(*pol));

    /* Policy selector */
    pol->sel.family = src_family;
    pol->sel.saddr = src_addr;
    pol->sel.daddr = dst_addr;
    pol->sel.sport = htons(src_port);
    pol->sel.dport = htons(dst_port);
    pol->sel.sport_mask = src_port ? 0xFFFF : 0;
    pol->sel.dport_mask = dst_port ? 0xFFFF : 0;
    pol->sel.proto = proto;
    pol->sel.prefixlen_s = (src_family == AF_INET) ? 32 : 128;
    pol->sel.prefixlen_d = (src_family == AF_INET) ? 32 : 128;

    pol->dir = dir;
    pol->action = XFRM_POLICY_ALLOW;
    pol->priority = 2000;

    pol->lft.soft_byte_limit = XFRM_INF;
    pol->lft.hard_byte_limit = XFRM_INF;
    pol->lft.soft_packet_limit = XFRM_INF;
    pol->lft.hard_packet_limit = XFRM_INF;

    /* SA template: tells kernel which SA to use */
    xfrm_address_t tsrc_addr, tdst_addr;
    uint16_t tsrc_family, tdst_family;
    if (parse_ip(tmpl_src, &tsrc_addr, &tsrc_family) < 0) {
        WARNING("Invalid template source IP: %s", tmpl_src);
        return -1;
    }
    if (parse_ip(tmpl_dst, &tdst_addr, &tdst_family) < 0) {
        WARNING("Invalid template destination IP: %s", tmpl_dst);
        return -1;
    }

    struct xfrm_user_tmpl tmpl;
    memset(&tmpl, 0, sizeof(tmpl));
    tmpl.id.daddr = tdst_addr;
    tmpl.id.spi = htonl(spi);
    tmpl.id.proto = IPPROTO_ESP;
    tmpl.saddr = tsrc_addr;
    tmpl.family = tsrc_family;
    tmpl.mode = XFRM_MODE_TRANSPORT;
    tmpl.reqid = spi;
    tmpl.aalgos = ~0u;
    tmpl.ealgos = ~0u;
    tmpl.calgos = ~0u;

    mnl_attr_put(nlh, XFRMA_TMPL, sizeof(tmpl), &tmpl);

    return xfrm_send_and_recv(nlh);
}

int xfrm_del_policy(const char *src_ip, const char *dst_ip,
                    uint16_t src_port, uint16_t dst_port, int proto,
                    int dir)
{
    char buf[XFRM_BUF_SIZE];
    struct nlmsghdr *nlh;
    struct xfrm_userpolicy_id *pol_id;
    xfrm_address_t src_addr, dst_addr;
    uint16_t src_family, dst_family;

    if (!xfrm_nl) {
        WARNING("XFRM netlink not initialized");
        return -1;
    }

    if (parse_ip(src_ip, &src_addr, &src_family) < 0) {
        WARNING("Invalid source IP: %s", src_ip);
        return -1;
    }
    if (parse_ip(dst_ip, &dst_addr, &dst_family) < 0) {
        WARNING("Invalid destination IP: %s", dst_ip);
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = XFRM_MSG_DELPOLICY;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = ++xfrm_seq;

    pol_id = (struct xfrm_userpolicy_id *)mnl_nlmsg_put_extra_header(nlh, sizeof(*pol_id));

    pol_id->sel.family = src_family;
    pol_id->sel.saddr = src_addr;
    pol_id->sel.daddr = dst_addr;
    pol_id->sel.sport = htons(src_port);
    pol_id->sel.dport = htons(dst_port);
    pol_id->sel.sport_mask = src_port ? 0xFFFF : 0;
    pol_id->sel.dport_mask = dst_port ? 0xFFFF : 0;
    pol_id->sel.proto = proto;
    pol_id->sel.prefixlen_s = (src_family == AF_INET) ? 32 : 128;
    pol_id->sel.prefixlen_d = (src_family == AF_INET) ? 32 : 128;
    pol_id->dir = dir;

    return xfrm_send_and_recv(nlh);
}

#endif /* USE_IPSEC */
