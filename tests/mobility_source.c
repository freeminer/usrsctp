/* SPDX-License-Identifier: BSD-2-Clause */
/* Model a new IPv4 source on an association established over global IPv6. */
#include <netinet/sctp_os.h>
#include <netinet/sctp_pcb.h>
#include <netinet/sctputil.h>

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
