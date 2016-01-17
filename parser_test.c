#include <libxml/parser.h>
#include <libxml/tree.h>
#include "parser.h"
#include "parsed_types.h"
#include "rule_list.h"
#include "utils.h"
#include "utlist.h"

static struct fw_rule_node* list = NULL;

int main(int argc, char **argv) {
        if (argc != 2)
                return(1);

        /*
         * this initialize the library and check potential ABI mismatches
         * between the version it was compiled for and the actual shared
         * library used.
         */
        LIBXML_TEST_VERSION

        parse(argv[1], &list);

	struct fw_rule_node* tmp; 
	  LL_FOREACH(list, tmp) {
                print_rule(tmp->rule);
	  }
        /*
         * Cleanup function for the XML library.
         */
        xmlCleanupParser();
	
	clear_list(list); 

        return(0);
}

