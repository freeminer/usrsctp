/*
 * Copyright (C) 2026 Freeminer contributors
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef _USER_ADDR_MONITOR_H_
#define _USER_ADDR_MONITOR_H_

void sctp_diagnostic(int warning, const char *message);
#if defined(__linux__) && !defined(__EMSCRIPTEN__) && (defined(INET) || defined(INET6))
void sctp_start_address_monitor(void);
void sctp_stop_address_monitor(void);
#endif

#endif
