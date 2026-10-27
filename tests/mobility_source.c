/* SPDX-License-Identifier: BSD-2-Clause */
/* Model a new IPv4 source on an association established over global IPv6. */
#include <netinet/sctp_os.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>
#include <netinet/sctp_asconf.h>
#include <netinet/sctp_output.h>

void
restrict_ipv4_sources(struct socket *so, int restricted)
{
	struct sctp_inpcb *inp;
	struct sctp_tcb *stcb;
	struct sctp_vrf *vrf;
	struct sctp_ifn *ifn;
	struct sctp_ifa *ifa;

	inp = (struct sctp_inpcb *)so->so_pcb;
	SCTP_INP_RLOCK(inp);
	stcb = LIST_FIRST(&inp->sctp_asoc_list);
	if (stcb == NULL) {
		SCTP_INP_RUNLOCK(inp);
		abort();
	}
	SCTP_TCB_LOCK(stcb);
	SCTP_INP_RUNLOCK(inp);
	stcb->asoc.scope.ipv4_local_scope = 0;
	if (restricted) {
		SCTP_IPI_ADDR_RLOCK();
		vrf = sctp_find_vrf(stcb->asoc.vrf_id);
		LIST_FOREACH(ifn, &vrf->ifnlist, next_ifn) {
			LIST_FOREACH(ifa, &ifn->ifalist, next_ifa) {
				if (ifa->address.sa.sa_family == AF_INET) {
					sctp_add_local_addr_restricted(stcb, ifa);
				}
			}
		}
		SCTP_IPI_ADDR_RUNLOCK();
	}
	SCTP_TCB_UNLOCK(stcb);
}

/* Model a cached source whose route no longer carries application DATA. */
int
pin_stale_ipv4_source(struct socket *so)
{
	struct sctp_inpcb *inp = (struct sctp_inpcb *)so->so_pcb;
	struct sctp_tcb *stcb;
	struct sctp_vrf *vrf;
	struct sctp_ifn *ifn;
	struct sctp_ifa *ifa = NULL, *selected = NULL, *old;
	struct sctp_nets *net;

	SCTP_INP_RLOCK(inp);
	stcb = LIST_FIRST(&inp->sctp_asoc_list);
	SCTP_TCB_LOCK(stcb);
	SCTP_INP_RUNLOCK(inp);
	net = stcb->asoc.primary_destination;
	if (net->ro._l_addr.sa.sa_family != AF_INET) {
		SCTP_TCB_UNLOCK(stcb);
		return (-1);
	}
	SCTP_IPI_ADDR_RLOCK();
	vrf = sctp_find_vrf(stcb->asoc.vrf_id);
	LIST_FOREACH(ifn, &vrf->ifnlist, next_ifn) {
		LIST_FOREACH(ifa, &ifn->ifalist, next_ifa) {
			if (ifa->address.sa.sa_family == AF_INET &&
			    !IN4_ISLOOPBACK_ADDRESS(&ifa->address.sin.sin_addr) &&
			    !(ifa->localifa_flags &
			    (SCTP_BEING_DELETED | SCTP_ADDR_IFA_UNUSEABLE | SCTP_ADDR_DEFER_USE))) {
				selected = ifa;
				break;
			}
		}
		if (selected != NULL) {
			break;
		}
	}
	if (selected != NULL) {
		atomic_add_int(&selected->refcount, 1);
	}
	SCTP_IPI_ADDR_RUNLOCK();
	if (selected == NULL) {
		SCTP_TCB_UNLOCK(stcb);
		return (-1);
	}
	old = net->ro._s_addr;
	net->ro._s_addr = selected;
	net->src_addr_selected = 1;
	if (old != NULL) {
		sctp_free_ifa(old);
	}
	SCTP_TCB_UNLOCK(stcb);
	return (0);
}


void
request_source_update(struct socket *so)
{
	struct sctp_inpcb *inp = (struct sctp_inpcb *)so->so_pcb;
	struct sctp_tcb *stcb;

	SCTP_INP_RLOCK(inp);
	stcb = LIST_FIRST(&inp->sctp_asoc_list);
	SCTP_TCB_LOCK(stcb);
	SCTP_INP_RUNLOCK(inp);
	sctp_send_asconf(stcb, stcb->asoc.primary_destination, SCTP_ADDR_NOT_LOCKED);
	sctp_chunk_output(inp, stcb, SCTP_OUTPUT_FROM_CONTROL_PROC, SCTP_SO_NOT_LOCKED);
	SCTP_TCB_UNLOCK(stcb);
}
