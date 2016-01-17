#ifndef FW_LA_COMMON_H
#define FW_LA_COMMON_H

#include <arpa/inet.h>
#include <stdio.h>

#define LA_CONN_SOCK "/tmp/fw_la_conn_sock"
#define LA_PKT_SOCK "/tmp/fw_la_pckt_sock"
#define LAB_SOCK "/tmp/fw_lab_sock"
#define FW_SOCK "/tmp/fw_firewall_sock"

typedef u_int16_t port_t;

union fw_address
{
	u_int32_t         v4;
	struct in6_addr   v6;
};

struct fw_tuple
{
	union fw_address src;
	union fw_address dst;
	union
	{
		struct {
			port_t src_port;
			port_t dst_port;
		} udp;
		struct {
			u_int8_t type;
			u_int8_t code;
		} icmp;
	};
};

struct fw_conn_info
{
	u_int32_t  msg_type;     /* NEW | UPDATE | DESTROY */

	struct fw_tuple orig;
	struct fw_tuple repl;

	u_int8_t  l3protonum;
	u_int8_t  protonum;
	u_int8_t  tcp_state;
	u_int32_t  status;       /* UNREPLIED | ASSURED | etc */
	u_int32_t  timeout;
	u_int32_t  id;
};

struct fw_pkt_info
{
	struct fw_tuple orig;
	u_int8_t   l3protonum;   /* IPv4 | IPv6 */
	u_int8_t   verdict;      /* see fw_dispatcher.h */
};
#endif // FW_LA_COMMON_H
