#ifndef RULES_LIST_H
#define RULES_LIST_H

#include "parsed_types.h"

struct fw_rule_node {
  struct fw_rule  rule;
  struct fw_rule_node  *next;
};

#endif
