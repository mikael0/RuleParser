#ifndef UTILS_H
#define UTILS_H

void clear_list(struct fw_rule_node* head);

void clear_rule(struct fw_rule* rulep);

void print_dump(const void *data, const u_int32_t len);

char* to_lower(char* str);

int case_ins_strcmp(char* str1, char* str2);

int atoi_s(char* s, int* result);

#endif
