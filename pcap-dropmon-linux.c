/*
 * Copyright (c) 2019 Mellanox Technologies
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 * products derived from this software without specific prior written
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "pcap-int.h"

#include <errno.h>
#include <stdio.h>
#include <time.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/net_dropmon.h>
#include <netlink/genl/genl.h>
#include <netlink/socket.h>

#define DROPMON_FAMILY "NET_DM"
#define DROPMON_IFACE "dropmon"
#define DROPMON_VER 2

/* Private data for per-opened instance */
struct pcap_dropmon {
	u_int	packets_read;	/* Count of packets read with recvfrom() */
	u_int   packets_nobufs; /* ENOBUFS counter */
	struct nl_sock *sk;
	uint32_t seq;
	int family;
};

static int
dropmon_config_set(pcap_t *handle, enum net_dm_alert_mode alert_mode)
{
	struct pcap_dropmon *handlep = handle->priv;
	uint32_t seq = handlep->seq++;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, 0, seq, handlep->family, 0,
			 NLM_F_REQUEST|NLM_F_ACK, NET_DM_CMD_CONFIG,
			 DROPMON_VER))
		goto genlmsg_put_failure;

	if (nla_put_u8(msg, NET_DM_ATTR_ALERT_MODE, alert_mode))
		goto nla_put_failure;

	/* Do not truncate packets */
	if (nla_put_u32(msg, NET_DM_ATTR_TRUNC_LEN, 0))
		goto nla_put_failure;

	/* Use default per-CPU queue length */
	if (nla_put_u32(msg, NET_DM_ATTR_QUEUE_LEN, 1000))
		goto nla_put_failure;

	return nl_send_sync(handlep->sk, msg);

nla_put_failure:
genlmsg_put_failure:
	nlmsg_free(msg);
	return -EMSGSIZE;
}

static int
dropmon_monitor(pcap_t *handle, uint8_t cmd)
{
	struct pcap_dropmon *handlep = handle->priv;
	uint32_t seq = handlep->seq++;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	if (!genlmsg_put(msg, 0, seq, handlep->family, 0,
			 NLM_F_REQUEST|NLM_F_ACK, cmd, DROPMON_VER))
		goto genlmsg_put_failure;

	if (nla_put_flag(msg, NET_DM_ATTR_SW_DROPS))
		goto nla_put_failure;

	if (nla_put_flag(msg, NET_DM_ATTR_HW_DROPS))
		goto nla_put_failure;

	return nl_send_sync(handlep->sk, msg);

nla_put_failure:
genlmsg_put_failure:
	nlmsg_free(msg);
	return -EMSGSIZE;
}

static int
dropmon_read(pcap_t *handle, int max_packets, pcap_handler callback,
	     u_char *user)
{
	struct pcap_dropmon *handlep = handle->priv;
	int count = 0;

	if (handle->break_loop) {
		handle->break_loop = 0;
		return PCAP_ERROR_BREAK;
	}

	while (count < max_packets || PACKET_COUNT_IS_UNLIMITED(max_packets)) {
		struct genlmsghdr *gnlh;
		struct pcap_pkthdr pkth;
		struct sockaddr_nl nla;
		struct nlmsghdr *nlh;
		struct nlattr *attr;
		unsigned char *buf;
		u_char *pktd;
		int err;

		err = nl_recv(handlep->sk, &nla, &buf, NULL);
		if (err < 0) {
			switch (errno) {
			case EINTR:
				continue;
			case ENOBUFS:
				handlep->packets_nobufs++;
				continue;
			default:
				pcap_fmt_errmsg_for_errno(handle->errbuf,
							  PCAP_ERRBUF_SIZE,
							  errno,
							  "Cannot receive packet");
				return PCAP_ERROR;
			}
		}

		nlh = (struct nlmsghdr *) buf;
		if (nlh->nlmsg_type != handlep->family)
			continue;

		gnlh = nlmsg_data(nlh);
		if (gnlh->cmd != NET_DM_CMD_PACKET_ALERT)
			continue;

		attr = nlmsg_find_attr(nlh, sizeof(struct genlmsghdr),
				       NET_DM_ATTR_PAYLOAD);
		if (!attr)
			continue;

		/*
		 * We run the filter on the encoded payload, but pass the
		 * entire netlink packet to the callback.
		 */
		pkth.caplen = pkth.len = nla_len(attr);
		gettimeofday(&pkth.ts, NULL);
		pktd = nla_data(attr);
		if (handle->fcode.bf_insns == NULL ||
		    pcap_filter(handle->fcode.bf_insns, pktd, pkth.len, pkth.caplen)) {
			pkth.caplen = pkth.len = nlh->nlmsg_len;
			pktd = (u_char *) buf;
			callback(user, &pkth, pktd);
			handlep->packets_read++;
			count++;
		}

		if (handle->break_loop) {
			handle->break_loop = 0;
			return PCAP_ERROR_BREAK;
		}
	}

	return count;
}

static int
dropmon_inject(pcap_t *handle, const void *buf _U_, int size _U_)
{
	snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
		 "Packet injection is not supported on dropmon devices");
	return PCAP_ERROR;
}

static int
dropmon_set_datalink(pcap_t *handle, int dlt)
{
	handle->linktype = dlt;

	return 0;
}

static int
dropmon_stats(pcap_t *handle, struct pcap_stat *stats)
{
	stats->ps_recv = handlep->packets_read;
	stats->ps_drop = handlep->packets_nobufs;
	stats->ps_ifdrop = 0;

	return 0;
}

static void
dropmon_cleanup(pcap_t *handle)
{
	struct pcap_dropmon *handlep = handle->priv;

	nl_socket_drop_memberships(handlep->sk, NET_DM_GRP_ALERT, NFNLGRP_NONE);
	dropmon_monitor(handle, NET_DM_CMD_STOP);
	dropmon_config_set(handle, NET_DM_ALERT_MODE_SUMMARY);
	nl_socket_free(sk);
}

static int
dropmon_activate(pcap_t *handle)
{
	struct pcap_dropmon *handlep = handle->priv;
	struct nl_sock *sk;
	int err;

	if (handle->snapshot <= 0 || handle->snapshot > MAXIMUM_SNAPLEN)
		handle->snapshot = MAXIMUM_SNAPLEN;

	handle->bufsize = handle->snapshot;
	handle->offset = 0;
	handle->read_op = dropmon_read;
	handle->inject_op = dropmon_inject;
	handle->setfilter_op = install_bpf_program; /* no kernel filtering */
	handle->setdirection_op = NULL;
	handle->set_datalink_op = dropmon_set_datalink;
	handle->getnonblock_op = pcap_getnonblock_fd;
	handle->setnonblock_op = pcap_setnonblock_fd;
	handle->stats_op = dropmon_stats;
	handle->cleanup_op = dropmon_cleanup;
	handle->linktype = DLT_NETLINK;

	sk = nl_socket_alloc();
	if (!sk) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Failed to allocate socket");
		return PCAP_ERROR;
	}

	err = genl_connect(sk);
	if (err) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Failed to connect socket");
		goto err_genl_connect;
	}

	err = nl_socket_set_msg_buf_size(sk, handle->bufsize);
	if (err) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Failed to set message buffer size");
		goto err_set_msg_buf_size;
	}

	if (handle->opt.buffer_size != 0) {
		err = nl_socket_set_buffer_size(sk, handle->opt.buffer_size, 0);
		if (err) {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				 "Failed to set receive buffer size");
			goto err_set_buffer_size;
		}
	}

	handlep->sk = sk;
	handlep->seq = (uint32_t) time(NULL);
	handlep->family = genl_ctrl_resolve(sk, DROPMON_FAMILY);

	err = dropmon_config_set(handle, NET_DM_ALERT_MODE_PACKET);
	if (err) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Failed to configure drop monitor");
		goto err_config_set;
	}

	err = dropmon_monitor(handle, NET_DM_CMD_START);
	if (err) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Failed to start monitoring");
		goto err_monitor;
	}

	err = nl_socket_add_memberships(sk, NET_DM_GRP_ALERT, NFNLGRP_NONE);
	if (err) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Failed to join multicast group");
		goto err_add_memberships;
	}

	handle->selectable_fd = nl_socket_get_fd(sk);

	return 0;

err_add_memberships:
	dropmon_monitor(handle, NET_DM_CMD_STOP);
err_monitor:
	dropmon_config_set(handle, NET_DM_ALERT_MODE_SUMMARY);
err_config_set:
err_set_buffer_size:
err_set_msg_buf_size:
err_genl_connect:
	nl_socket_free(sk);
	return PCAP_ERROR;
}

pcap_t *
dropmon_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *p;

	if (strncmp(device, DROPMON_IFACE, strlen(DROPMON_IFACE))) {
		*is_ours = 0;
		return NULL;
	}

	*is_ours = 1;

	p = pcap_create_common(ebuf, sizeof(struct pcap_dropmon));
	if (!p)
		return NULL;

	p->activate_op = dropmon_activate;

	return p;
}

int
dropmon_findalldevs(pcap_if_list_t *devlistp, char *err_str)
{
	struct nl_sock *sk;
	int err, family;

	sk = nl_socket_alloc();
	if (!sk) {
		snprintf(err_str, PCAP_ERRBUF_SIZE, "Failed to allocate socket");
		return -1;
	}

	err = genl_connect(sk);
	if (err) {
		snprintf(err_str, PCAP_ERRBUF_SIZE, "Failed to connect socket");
		goto err_genl_connect;
	}

	family = genl_ctrl_resolve(sk, DROPMON_FAMILY);
	if (family < 0) {
		snprintf(err_str, PCAP_ERRBUF_SIZE, "NET_DM not available");
		goto err_genl_ctrl_resolve;
	}

	nl_socket_free(sk);

	if (add_dev(devlistp, DROPMON_IFACE,
		    PCAP_IF_CONNECTION_STATUS_NOT_APPLICABLE,
		    "Linux dropmon (NET_DM) interface", err_str) == NULL)
		return -1;

	return 0;

err_genl_ctrl_resolve:
err_genl_connect:
	nl_socket_free(sk);
	return -1;
}
