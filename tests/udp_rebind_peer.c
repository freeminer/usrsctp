/* SPDX-License-Identifier: BSD-2-Clause */
/* Endpoint for udp_rebind.py; one independent usrsctp stack per process. */
#include <usrsctp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef SCTP_TEST_SOURCE_CACHE
int pin_stale_ipv4_source(struct socket *);
void request_source_update(struct socket *);
#endif

#ifdef SCTP_TEST_PRIVATE_SOURCE
void restrict_ipv4_sources(struct socket *, int);
#endif

static void diagnostic(int warning, const char *message)
{
	(void)warning;
	fprintf(stderr, "%s\n", message);
}

static void check(int result, const char *operation)
{
	if (result < 0) {
		perror(operation);
		exit(1);
	}
}

int main(int argc, char **argv)
{
	struct socket *sock, *listener = NULL;
	struct sockaddr_storage address;
	struct sockaddr_in *address4 = (struct sockaddr_in *)&address;
	struct sockaddr_in6 *address6 = (struct sockaddr_in6 *)&address;
	socklen_t address_length;
	struct sctp_udpencaps encaps;
	struct sctp_assocparams association;
	struct sctp_rtoinfo rto;
	int server, tick, family, dual, one = 1;
#ifdef SCTP_TEST_PRIVATE_SOURCE
	int restricted = 0;
#endif

	if (argc != 5)
		return 2;
	server = strcmp(argv[1], "server") == 0;
	dual = strcmp(argv[4], "dual") == 0 || strcmp(argv[4], "dual4") == 0;
	family = dual || strcmp(argv[4], "6") == 0 ? AF_INET6 : AF_INET;
	address_length = family == AF_INET6 ? sizeof(*address6) : sizeof(*address4);
	setvbuf(stdout, NULL, _IOLBF, 0);
	usrsctp_set_diagnostic_logger(diagnostic);
	usrsctp_init((uint16_t)atoi(argv[2]), NULL, NULL);
	usrsctp_sysctl_set_sctp_blackhole(2);
	usrsctp_sysctl_set_sctp_auth_enable(1);
	usrsctp_sysctl_set_sctp_asconf_enable(1);
	usrsctp_sysctl_set_sctp_auto_asconf(1);
	usrsctp_sysctl_set_sctp_inits_include_nat_friendly(1);
	usrsctp_sysctl_set_sctp_mobility_base(1);
	usrsctp_sysctl_set_sctp_mobility_fasthandoff(1);
	usrsctp_sysctl_set_sctp_heartbeat_interval_default(500);
	sock = usrsctp_socket(family, SOCK_STREAM, IPPROTO_SCTP, NULL, NULL, 0, NULL);
	if (sock == NULL)
		return 1;
	check(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_NODELAY, &one, sizeof(one)),
			"nodelay");
	memset(&association, 0, sizeof(association));
	association.sasoc_asocmaxrxt = UINT16_MAX;
	check(usrsctp_setsockopt(
				  sock, IPPROTO_SCTP, SCTP_ASSOCINFO, &association, sizeof(association)),
			"associnfo");
	memset(&rto, 0, sizeof(rto));
	rto.srto_initial = 200;
	rto.srto_min = 100;
	rto.srto_max = 1000;
	check(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_RTOINFO, &rto, sizeof(rto)), "rto");
	memset(&encaps, 0, sizeof(encaps));
	encaps.sue_address.ss_family = family;
	encaps.sue_port = htons((uint16_t)atoi(argv[3]));
	check(usrsctp_setsockopt(sock, IPPROTO_SCTP, SCTP_REMOTE_UDP_ENCAPS_PORT, &encaps,
				  sizeof(encaps)),
			"encap");
	memset(&address, 0, sizeof(address));
	if (family == AF_INET6) {
		address6->sin6_family = AF_INET6;
		address6->sin6_addr = dual ? in6addr_any : in6addr_loopback;
		address6->sin6_port = htons(server ? 5001 : 5002);
	} else {
		address4->sin_family = AF_INET;
		address4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		address4->sin_port = htons(server ? 5001 : 5002);
	}
#ifdef SCTP_TEST_SOURCE_CACHE
	if (server)
		address6->sin6_addr = in6addr_loopback;
#endif
	check(usrsctp_bind(sock, (struct sockaddr *)&address, address_length), "bind");
#ifdef SCTP_TEST_SOURCE_CACHE
	if (server) {
		struct sockaddr_in local4 = {0};
		local4.sin_family = AF_INET;
		local4.sin_port = htons(5001);
		local4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		check(usrsctp_bindx(sock, (struct sockaddr *)&local4, 1, SCTP_BINDX_ADD_ADDR),
				"bind IPv4");
	}
#endif
	check(usrsctp_set_non_blocking(sock, 1), "nonblocking");
	if (server) {
		check(usrsctp_listen(sock, 1), "listen");
		listener = sock;
		sock = NULL;
	} else {
		if (family == AF_INET6)
			address6->sin6_port = htons(5001);
		else
			address4->sin_port = htons(5001);
		if (dual) {
			union
			{
				struct sockaddr_storage alignment;
				unsigned char
						bytes[sizeof(struct sockaddr_in6) + sizeof(struct sockaddr_in)];
			} peers;
			struct sockaddr_in6 first;
			struct sockaddr_in second;
			memset(&first, 0, sizeof(first));
			first.sin6_family = AF_INET6;
			first.sin6_addr = in6addr_loopback;
			first.sin6_port = htons(5001);
			memset(&second, 0, sizeof(second));
			second.sin_family = AF_INET;
			inet_pton(AF_INET,
					getenv("SCTP_TEST_IPV4") != NULL ? getenv("SCTP_TEST_IPV4")
													 : "127.0.0.2",
					&second.sin_addr);
			second.sin_port = htons(5001);
			if (strcmp(argv[4], "dual4") == 0) {
				memcpy(peers.bytes, &second, sizeof(second));
				memcpy(peers.bytes + sizeof(second), &first, sizeof(first));
			} else {
				memcpy(peers.bytes, &first, sizeof(first));
				memcpy(peers.bytes + sizeof(first), &second, sizeof(second));
			}
			if (usrsctp_connectx(sock, (struct sockaddr *)peers.bytes, 2, NULL) < 0 &&
					errno != EINPROGRESS)
				check(-1, "connectx");
		} else if (usrsctp_connect(sock, (struct sockaddr *)&address, address_length) <
						   0 &&
				   errno != EINPROGRESS) {
			check(-1, "connect");
		}
	}
	puts("READY");
	for (tick = 0; tick < 3000; ++tick) {
		char buffer[128];
		struct sctp_rcvinfo info;
		socklen_t length = sizeof(info);
		unsigned int type = 0;
		int flags = 0;
		ssize_t size;
		if (sock == NULL) {
			sock = usrsctp_accept(listener, NULL, NULL);
			if (sock != NULL) {
				check(usrsctp_set_non_blocking(sock, 1), "accepted nonblocking");
				puts("ACCEPTED");
			}
		} else {
#ifdef SCTP_TEST_SOURCE_CACHE
			if (server && tick % 10 == 0) {
				int n = snprintf(buffer, sizeof(buffer), "S%d", tick);
				(void)usrsctp_sendv(
						sock, buffer, n, NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
			}
			if (!server && tick == 40) {
				check(pin_stale_ipv4_source(sock), "pin source");
				puts("PINNED");
			}
			if (!server && tick == 60)
				request_source_update(sock);
#endif
			if (!server && tick % 10 == 0) {
				int n = snprintf(buffer, sizeof(buffer), "%d", tick);
#ifdef SCTP_TEST_SOURCE_CACHE
				struct sctp_sendv_spa spa = {0};
				spa.sendv_flags = SCTP_SEND_SNDINFO_VALID | SCTP_SEND_PRINFO_VALID;
				spa.sendv_sndinfo.snd_sid = 7;
				spa.sendv_sndinfo.snd_flags = SCTP_UNORDERED | SCTP_EOR;
				spa.sendv_prinfo.pr_policy = SCTP_PR_SCTP_RTX;
				(void)usrsctp_sendv(
						sock, buffer, n, NULL, 0, &spa, sizeof(spa), SCTP_SENDV_SPA, 0);
#else
				(void)usrsctp_sendv(
						sock, buffer, n, NULL, 0, NULL, 0, SCTP_SENDV_NOINFO, 0);
#endif
			}
			size = usrsctp_recvv(sock, buffer, sizeof(buffer), NULL, NULL, &info, &length,
					&type, &flags);
			if (size > 0 && !(flags & MSG_NOTIFICATION)) {
#ifdef SCTP_TEST_PRIVATE_SOURCE
				if (dual && !restricted && tick >= 40) {
					restrict_ipv4_sources(sock, !server);
					restricted = 1;
				}
#endif
				if (server)
					check((int)usrsctp_sendv(sock, buffer, size, NULL, 0, NULL, 0,
								  SCTP_SENDV_NOINFO, 0),
							"echo");
				else
					printf("RX %.*s\n", (int)size, buffer);
			} else if (size == 0) {
				puts("CLOSED");
				break;
			}
		}
		usleep(10000);
	}
	return 0;
}
