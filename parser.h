#ifndef PARSER_H
#define PARSER_H

#include "rule_list.h"
#include "parsed_types.h"

void print_rule(struct fw_rule rule);
void parse(const char* filename, struct fw_rule_node** list);

#endif
