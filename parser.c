#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "parsed_types.h"
#include "rule_list.h"
#include "utils.h"
#include "utlist.h"

#define XML_ROOT "rule_list"
#define RULE_CHILDREN_COUNT_MAX 2

#define NECESSARY_RULE_PROPS_COUNT 4
#define NECESSARY_INDICATOR_PROPS_COUNT 2
#define NECESSARY_POSTDETECTION_PROPS_COUNT 1

#define SRC_PORT_FL 1
#define DST_PORT_FL 2
#define ICMP_TYPE_FL 4
#define ICMP_CODE_FL 8

#define IS_SRCDST_PORT(p) p < 4
#define IS_ICMP(p) p >= 4 

enum parse_ret_code_t{
	SUCCESS = 0,
	RULE_ERROR,
	INDICATOR_ERROR,
	POSTDETECTION_ERROR
};

void print_rule(struct fw_rule rule) 
{	
	char ip[17];

	printf("<----------rule---------->\n");
	printf("code: %i\n", rule.code);
	printf("name: %s\n", rule.name);
	printf("interval: %i\n", rule.opt_interval);
	printf("count: %i\n", rule.opt_count);
	printf("block_period: %i\n", rule.opt_block_period);
	printf("\tindicators:\n");
	printf("protocol: %i\n", rule.opt_protonum);
	printf("l3protonum: %i\n", rule.l3protonum);
	printf("flag: %i\n", rule.tcp_state);
	if (inet_ntop(rule.l3protonum, &rule.orig.src, ip, 17) != NULL)
		printf("src_ip: %s\n", ip);
	if (inet_ntop(rule.l3protonum, &rule.orig.dst, ip, 17) != NULL)
		printf("dst_ip: %s\n", ip);
	printf("dst_port: %u\n", rule.orig.udp.dst_port);
	printf("src_port: %u\n", rule.orig.udp.src_port);
	printf("icmp_code: %hhu\n", rule.orig.icmp.code);
	printf("icmp_type: %u\n", rule.orig.icmp.type);
	printf("track: %i\n", rule.track);
	printf("\tpost_detection:\n");
	printf("action: %i\n", rule.action);
	printf("<------------------------>\n");
}

static enum parse_ret_code_t parseNodeProps(xmlNodePtr cur, struct fw_rule_node** rule_list) {
	
	static struct fw_rule new_rule;
	static char rule_children_parsed = 0;
	
	if (!xmlStrcmp(cur->name,(const xmlChar*)"rule")) {
		xmlAttr* attribute = cur->properties;
		int props_counter = 0;
		
		new_rule.opt_block_period = 0;

		int name_set = 0;
		while(attribute && attribute->name && attribute->children)
		{	
			xmlChar* value = xmlNodeListGetString(cur->doc, attribute->children, 1);
			if (!xmlStrcmp(attribute->name,(const xmlChar*)"code")) 
			{
				props_counter++;	
				if (!atoi_s(value, (int*)&new_rule.code)) {
					if (name_set) {
						fprintf(stderr, "rule: %s Invalid code %s\n", new_rule.name, value);
						free(new_rule.name);
					}
					else
						fprintf(stderr, "Invalid code %s\n", value);
					return RULE_ERROR;

				}
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"name"))
			{
				props_counter++;	
				name_set = 1;
				new_rule.name = (char*)calloc(sizeof(char), strlen(value));
				strcpy(new_rule.name, value);				
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"interval"))
			{
				props_counter++;	
				if (!atoi_s(value, (int*)&new_rule.opt_interval)) {
					if (name_set) {
						fprintf(stderr, "rule: %s Invalid interval %s\n", new_rule.name, value);
						free(new_rule.name);
					}
					else
						fprintf(stderr, "Invalid interval %s\n", value);
					return RULE_ERROR;
				}				
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"count"))
			{
				props_counter++;	
				if (!atoi_s(value, (int*)&new_rule.opt_count)) {
					if (name_set) {
						fprintf(stderr, "rule: %s Invalid count %s\n", new_rule.name, value);
						free(new_rule.name);
					}
					else
						fprintf(stderr, "Invalid count %s\n", value);
					return RULE_ERROR;
				}				
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"block_period"))
			{
				if (!atoi_s(value, (int*)&new_rule.opt_block_period)) {
					if (name_set) {
						fprintf(stderr, "rule: %s Invalid block_period %s\n", new_rule.name, value);
						free(new_rule.name);
					}
					else
						fprintf(stderr, "Invalid block_period %s\n", value);
					return RULE_ERROR;
				}				
			}
			else {
				if (name_set) {
					fprintf(stderr, "rule: %s Invalid attribute %s\n", new_rule.name, attribute->name);
					free(new_rule.name);
				}
				else
					fprintf(stderr, "Invalid attribute %s\n", attribute->name);
				return RULE_ERROR;
			}
			xmlFree(value); 	
			attribute = attribute->next;
		}
		xmlFree(attribute);
		if (props_counter < NECESSARY_RULE_PROPS_COUNT)
		{
			fprintf(stderr, "Invalid rule %s\n", new_rule.name);
			free(new_rule.name);
			return RULE_ERROR;
		}
		rule_children_parsed = 0;
	}
	else if (!xmlStrcmp(cur->name,(const xmlChar*)"indicators")) {
		xmlAttr* attribute = cur->properties;
		int props_counter = 0;
		int port_flag = 0;

		new_rule.orig.src.v4 = LA_ANY_IP4;
		new_rule.orig.dst.v4 = LA_ANY_IP4;
		new_rule.orig.udp.src_port = LA_ANY_PORT;
		new_rule.orig.udp.dst_port = LA_ANY_PORT;
		new_rule.tcp_state = TCP_FW_LA_NONE;
		new_rule.track = 0;
		new_rule.icmp_type = ICMP_NONE;
		new_rule.icmp_code = 0;

		while(attribute && attribute->name && attribute->children)
		{
			xmlChar* value = xmlNodeListGetString(cur->doc, attribute->children, 1);
			if (!xmlStrcmp(attribute->name,(const xmlChar*)"protocol"))
			{ 
				props_counter++;
				if (!case_ins_strcmp(value, "TCP")) {
					new_rule.opt_protonum = IPPROTO_TCP;
				}					
				else if (!case_ins_strcmp(value, "UDP")) {
					new_rule.opt_protonum = IPPROTO_UDP;
				}					
				else if (!case_ins_strcmp(value, "ICMP")) {
					new_rule.opt_protonum = IPPROTO_ICMP;
				}					
				else {
					fprintf(stderr, "rule: %s Invalid protocol\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"l3protonum"))
			{ 
				props_counter++;
				if (!case_ins_strcmp(value, "AF_INET")) {
					new_rule.l3protonum = AF_INET;				
				}
				else if (!case_ins_strcmp(value, "AF_INET6")) {
					new_rule.l3protonum = AF_INET6;				
				}
				else {
					fprintf(stderr, "rule: %s Invalid l3protonum\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"flag")) 
			{
				if (!case_ins_strcmp(value, "SYN_SENT")) {
					new_rule.tcp_state = TCP_FW_LA_SYN_SENT;
				}
				else if (!case_ins_strcmp(value, "SYN_RECV")) {
					new_rule.tcp_state = TCP_FW_LA_SYN_RECV;
				}
				else if (!case_ins_strcmp(value, "ESTABLISHED")) {
					new_rule.tcp_state = TCP_FW_LA_ESTABLISHED;
				}
				else if (!case_ins_strcmp(value, "FIN_WAIT")) {
					new_rule.tcp_state = TCP_FW_LA_FIN_WAIT;
				}
				else if (!case_ins_strcmp(value, "CLOSE_WAIT")) {
					new_rule.tcp_state = TCP_FW_LA_CLOSE_WAIT;
				}
				else if (!case_ins_strcmp(value, "LAST_ACK")) {
					new_rule.tcp_state = TCP_FW_LA_LAST_ACK;
				}
				else if (!case_ins_strcmp(value, "TIME_WAIT")) {
					new_rule.tcp_state = TCP_FW_LA_TIME_WAIT;
				}
				else if (!case_ins_strcmp(value, "CLOSE")) {
					new_rule.tcp_state = TCP_FW_LA_CLOSE;
				}
				else if (!case_ins_strcmp(value, "LISTEN")) {
					new_rule.tcp_state = TCP_FW_LA_LISTEN;
				}
				else if (!case_ins_strcmp(value, "SYN_SENT2")) {
					new_rule.tcp_state = TCP_FW_LA_SYN_SENT2;
				}
				else if (!case_ins_strcmp(value, "MAX")) {
					new_rule.tcp_state = TCP_FW_LA_MAX;
				}
				else if (!case_ins_strcmp(value, "IGNORE")) {
					new_rule.tcp_state = TCP_FW_LA_IGNORE;
				}
				else {
					fprintf(stderr, "rule: %s Invalid flag\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"dst_ip")) 
			{
				if (strstr(value, "."))
				{
					if (inet_pton(AF_INET, value, &new_rule.orig.dst.v4) != 1)
					{
						fprintf(stderr, "rule: %s invalid ipv4 address: %s\n", new_rule.name, value);
						return;
					}
				}
				else
				{
					if (inet_pton(AF_INET6, value, &new_rule.orig.dst.v6) != 1)
					{
						fprintf(stderr, "rule: %s invalid ipv6 address: %s\n", new_rule.name, value);
						return;
					}

				}
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"src_ip")) 
			{
				if (strstr(value, "."))
				{
					if (inet_pton(AF_INET, value, &new_rule.orig.src.v4) != 1)
					{
						fprintf(stderr, "rule: %s invalid ipv4 address: %s\n", new_rule.name, value);
						return;
					}
				}
				else
				{
					if (inet_pton(AF_INET6, value, &new_rule.orig.src.v6) != 1)
					{
						fprintf(stderr, "rule: %s invalid ipv6 address: %s\n", new_rule.name, value);
						return;
					}

				}
			}	
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"src_port")) { 
				if (port_flag && IS_ICMP(port_flag)) {
					fprintf(stderr, "rule: %s src_port unexpected\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
				port_flag += SRC_PORT_FL;	
				if (!atoi_s(value, (int*)&new_rule.orig.udp.src_port)) {
					fprintf(stderr, "rule: %s Invalid indicator src_port %s\n", new_rule.name, value);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}				
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"dst_port")) {
				if (port_flag && IS_ICMP(port_flag)) {
					fprintf(stderr, "rule: %s dst_port unexpected\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
				port_flag += DST_PORT_FL;	
				if (!atoi_s(value, (int*)&new_rule.orig.udp.dst_port)) {
					fprintf(stderr, "rule: %s Invalid indicator dst_port %s\n", new_rule.name, value);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}				
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"track")) 
			{
				if (!case_ins_strcmp(value, "BY_SRC"))
					new_rule.track = LARF_TRACK_BY_SRC;	
				else if (!case_ins_strcmp(value, "BY_DST"))
					new_rule.track = LARF_TRACK_BY_DST;
				else if (!case_ins_strcmp(value, "BY_RULE"))
					new_rule.track = LARF_TRACK_BY_RULE;
				else {
					fprintf(stderr, "rule: %s Invalid track\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"icmp_type"))
			{
				if (port_flag && IS_SRCDST_PORT(port_flag)) {
					fprintf(stderr, "rule: %s icmp_type unexpected\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
				port_flag += ICMP_TYPE_FL;	
				if (!case_ins_strcmp(value, "ECHOREPLY")) {
					new_rule.orig.icmp.type = ICMP_ECHOREPLY;	
				}	
				else if (!case_ins_strcmp(value, "DEST_UNREACH")) {
					new_rule.orig.icmp.type = ICMP_DEST_UNREACH;	
				}	
				else if (!case_ins_strcmp(value, "SOURCE_QUENCH")) {
					new_rule.orig.icmp.type = ICMP_SOURCE_QUENCH;	
				}	
				else if (!case_ins_strcmp(value, "REDIRECT")) {
					new_rule.orig.icmp.type = ICMP_REDIRECT;	
				}	
				else if (!case_ins_strcmp(value, "ECHO")) {
					new_rule.orig.icmp.type = ICMP_ECHO;	
				}	
				else if (!case_ins_strcmp(value, "TIME_EXCEEDED")) {
					new_rule.orig.icmp.type = ICMP_TIME_EXCEEDED;	
				}	
				else if (!case_ins_strcmp(value, "PARAMETERPROB")) {
					new_rule.orig.icmp.type = ICMP_PARAMETERPROB;	
				}	
				else if (!case_ins_strcmp(value, "TIMESTAMP")) {
					new_rule.orig.icmp.type = ICMP_TIMESTAMP;	
				}	
				else if (!case_ins_strcmp(value, "TIMESTAMPREPLY")) {
					new_rule.orig.icmp.type = ICMP_TIMESTAMPREPLY;	
				}	
				else if (!case_ins_strcmp(value, "INFO_REQUEST")) {
					new_rule.orig.icmp.type = ICMP_INFO_REQUEST;	
				}	
				else if (!case_ins_strcmp(value, "INFO_REPLY")) {
					new_rule.orig.icmp.type = ICMP_INFO_REPLY;	
				}	
				else if (!case_ins_strcmp(value, "ADDRESS")) {
					new_rule.orig.icmp.type = ICMP_ADDRESS;
				}	
				else if (!case_ins_strcmp(value, "ADDRESSREPLY")) {
					new_rule.orig.icmp.type = ICMP_ADDRESSREPLY;
				}	
				else if (!case_ins_strcmp(value, "ADDRESSREPLY")) {
					new_rule.orig.icmp.type = ICMP_ADDRESSREPLY;
				}	
				else {
					fprintf(stderr, "rule: %s Invalid icmp_type\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
			}
			else if (!xmlStrcmp(attribute->name,(const xmlChar*)"icmp_code"))
			{
				if (port_flag && IS_SRCDST_PORT(port_flag)) {
					fprintf(stderr, "rule: %s icmp_code unexpected\n", new_rule.name);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}
				port_flag += ICMP_CODE_FL;
				if (!atoi_s(value, (int*)&new_rule.orig.icmp.code)) {
					fprintf(stderr, "rule: %s Invalid indicator icmp_code %s\n", new_rule.name, value);
					free(new_rule.name);
					return INDICATOR_ERROR;
				}				
			}
			else {
				fprintf(stderr, "rule: %s Invalid indicator attribute %s\n", new_rule.name, attribute->name);
				free(new_rule.name);
				return INDICATOR_ERROR;
			}
			xmlFree(value); 	
			attribute = attribute->next;
		}
		xmlFree(attribute);
		if (props_counter < NECESSARY_INDICATOR_PROPS_COUNT)
		{
			fprintf(stderr, "rule: %s Invalid indicator: necessary field is missing\n", new_rule.name);
			free(new_rule.name);
			return INDICATOR_ERROR;
		}
		rule_children_parsed++;
		if (rule_children_parsed == RULE_CHILDREN_COUNT_MAX) 
		{
			struct fw_rule_node* tmp = (struct fw_rule_node*)calloc(sizeof(struct fw_rule_node), 1); 
			memcpy(&(tmp->rule), &new_rule, sizeof(struct fw_rule)); 
			LL_APPEND(*rule_list, tmp);
			rule_children_parsed = 0;	
			clear_rule(&new_rule);
		}
	}
	else if (!xmlStrcmp(cur->name,(const xmlChar*)"post_detection")) {
		xmlAttr* attribute = cur->properties;
		int props_counter = 0;

		new_rule.action = 0;

		while(attribute && attribute->name && attribute->children)
		{
			xmlChar* value = xmlNodeListGetString(cur->doc, attribute->children, 1);
			if (!xmlStrcmp(attribute->name,(const xmlChar*)"action")) 
			{
				props_counter++;
				if (!case_ins_strcmp(value, "DROP"))
					new_rule.action = LARF_ACTION_DROP;
				else if (!case_ins_strcmp(value, "REJECT"))
					new_rule.action = LARF_ACTION_REJECT;
				else {
					fprintf(stderr, "rule: %s Invalid post_detection\n", new_rule.name);
					free(new_rule.name);
					return POSTDETECTION_ERROR;
				}
			}
			else {
				fprintf(stderr, "rule: %s Invalid post_detection attribute %s\n", new_rule.name, attribute->name);
				free(new_rule.name);
				return POSTDETECTION_ERROR;
			}
			xmlFree(value);
			attribute = attribute->next;
		}
		xmlFree(attribute);
		if (props_counter < NECESSARY_POSTDETECTION_PROPS_COUNT)
		{
			fprintf(stderr, "rule: %s Invalid post_detection: necessary field is missing\n", new_rule.name);
			free(new_rule.name);
			return POSTDETECTION_ERROR;
		}
		rule_children_parsed++;
		if (rule_children_parsed == RULE_CHILDREN_COUNT_MAX) 
		{
			struct fw_rule_node* tmp = (struct fw_rule_node*)calloc(sizeof(struct fw_rule_node), 1); 
			memcpy(&(tmp->rule), &new_rule, sizeof(struct fw_rule));
			LL_APPEND(*rule_list, tmp);
			rule_children_parsed = 0;	
			clear_rule(&new_rule);
		}
	}
}

static void parseNode(xmlNodePtr cur, struct fw_rule_node** rule_list) {

	static int c = 0;

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {
		if (parseNodeProps(cur, rule_list) == SUCCESS);		
		parseNode(cur, rule_list);			
		cur = cur->next;
	}	

}

void parse(const char *filename, struct fw_rule_node** rule_list) {
	xmlDocPtr doc; 
	xmlNodePtr cur;

	doc = xmlReadFile(filename, NULL, 0);
	if (doc == NULL) {
		fprintf(stderr, "Failed to parse %s\n", filename);
		return;
	}

	cur = xmlDocGetRootElement(doc);

	if (cur == NULL) {
		fprintf(stderr,"empty document\n");
		xmlFreeDoc(doc);
		return;
	}

	if (xmlStrcmp(cur->name, (const xmlChar *) XML_ROOT)) {
		fprintf(stderr,"document of the wrong type, root node is not %s\n", XML_ROOT);
		xmlFreeDoc(doc);
		return;
	}

	cur = cur->xmlChildrenNode;
	while (cur != NULL) {

		if (parseNodeProps(cur, rule_list) == SUCCESS)
			parseNode(cur, rule_list);	

		cur = cur->next;
	}

	xmlFreeDoc(doc);
}
