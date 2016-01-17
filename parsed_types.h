#ifndef PARSED_TYPES_H
#define PARSED_TYPES_H

#include "fw_la_common.h"

#define LA_ANY_IP4  0
#define LA_ANY_PORT 0

enum fw_la_tcp_state {
	TCP_FW_LA_NONE, /* обозначение в xml:  NONE */
	TCP_FW_LA_SYN_SENT, /* обозначение в xml:  SYN_SENT */
	TCP_FW_LA_SYN_RECV, /* обозначение в xml:  SYN_RECV */
	TCP_FW_LA_ESTABLISHED, /* обозначение в xml: ESTABLISHED */
	TCP_FW_LA_FIN_WAIT, /* обозначение в xml: FIN_WAIT */
	TCP_FW_LA_CLOSE_WAIT, /* обозначение в xml: CLOSE_WAIT */
	TCP_FW_LA_LAST_ACK, /* обозначение в xml: LAST_ACK */
	TCP_FW_LA_TIME_WAIT, /* обозначение в xml: TIME_WAIT */
	TCP_FW_LA_CLOSE, /* обозначение в xml:  CLOSE */
	TCP_FW_LA_LISTEN,   /* obsolete */ /* обозначение в xml: LISTEN */
#define TCP_FW_LA_SYN_SENT2   TCP_FW_LA_LISTEN /* обозначение в xml: SYN_SENT2  */
	TCP_FW_LA_MAX, /* обозначение в xml:  MAX */
	TCP_FW_LA_IGNORE /* обозначение в xml: IGNORE */
};

enum fw_la_icmp_type
{
	ICMP_ECHOREPLY = 0, /* обозначение в xml: ECHOREPLY */
	ICMP_DEST_UNREACH = 3, /* обозначение в xml: DEST_UNREACH */
	ICMP_SOURCE_QUENCH = 4, /* обозначение в xml: SOURCE_QUENCH */
	ICMP_REDIRECT = 5, /* обозначение в xml: REDIRECT */
	ICMP_ECHO = 8, /* обозначение в xml: ECHO */
	ICMP_TIME_EXCEEDED = 11, /* обозначение в xml: TIME_EXCEEDED */
	ICMP_PARAMETERPROB = 12, /* обозначение в xml: PARAMETERPROB */
	ICMP_TIMESTAMP = 13, /* обозначение в xml: TIMESTAMP */
	ICMP_TIMESTAMPREPLY = 14, /* обозначение в xml: TIMESTAMPREPLY */
	ICMP_INFO_REQUEST = 15, /* обозначение в xml: INFO_REQUEST */
	ICMP_INFO_REPLY = 16, /* обозначение в xml: INFO_REPLY */
	ICMP_ADDRESS = 17, /* обозначение в xml: ADDRESS */
	ICMP_ADDRESSREPLY = 18, /* обозначение в xml: ADDRESSREPLY */
	ICMP_NONE = 128, /* инициализирующее значение */
};

enum fw_la_rule_actions
{
	LARF_ACTION_DROP = 1, /* обозначение в xml: DROP */
	LARF_ACTION_REJECT /* обозначение в xml: REJECT */
};

enum fw_la_rule_track
{
	LARF_TRACK_BY_SRC = 1, /* обозначение в xml: BY_SRC */
	LARF_TRACK_BY_DST, /* обозначение в xml: BY_DST */
	LARF_TRACK_BY_RULE /* обозначение в xml: BY_RULE */
};

struct fw_rule
{
	char  *name;
	u_int32_t  code;
	struct fw_tuple  orig;
	u_int8_t  l3protonum;     /* AF_INET or AF_INET6 */
	u_int8_t  opt_protonum;   /* IPPROTO_UDP, IPPROTO_TCP or IPPROTO_ICMP */
	u_int8_t  tcp_state;      /* see enum fw_la_tcp_state */
	u_int16_t icmp_type; /* see /usr/include/linux/icmp.h */
	u_int16_t icmp_code;
	u_int8_t  track;          /* see enum fw_la_rule_track */
	u_int8_t  action;         /* see enum fw_la_rule_actions */
	u_int32_t  opt_block_period;  /* in seconds */
	u_int32_t  opt_count;
	u_int32_t  opt_interval;      /* in seconds */
};

#endif
