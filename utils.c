#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>

#include "parser.h"
#include "parsed_types.h"
#include "rule_list.h"
#include "utlist.h"


void clear_rule(struct fw_rule* rulep) {
	memset(rulep, 0, sizeof(struct fw_rule));
}

void clear_list(struct fw_rule_node* list) {
	
	struct fw_rule_node* curr;
	LL_FOREACH(list, curr) {
		LL_DELETE(list, curr);	
		free(curr->rule.name);
		free(curr);
	}	
}

void print_dump(const void *data, const u_int32_t len)
{
  int i;
  for (i = 0; i < len; ++i) {
    printf("%02x", *(char*)(data + i));
  }
}
	
char* to_lower(char* str) 
{
	char* p = str;	

	for (; *str; str++) {
		*str = tolower(*str);
	}  
	
	return p;
}

int case_ins_strcmp(char* str1, char* str2) {

        char* tmp1 = (char*)calloc(sizeof(char), strlen(str1));
        char* tmp2 = (char*)calloc(sizeof(char), strlen(str2));
        strcpy(tmp1, str1);
        strcpy(tmp2, str2);

        int result = strcmp(to_lower(tmp1), to_lower(tmp2));

        free(tmp1);
        free(tmp2);

        return result;
}

/**
	1 - SUCCESS
	0 - FAIL
**/
int atoi_s(char* str, int* result) {	
	
	int res = strtol(str, NULL, 10);	
	*result = res;
	if (res == 0) {
		if (!strcmp(str, "0"))	
			return 1;
		return 0;
	}
		
	return 1;
}

