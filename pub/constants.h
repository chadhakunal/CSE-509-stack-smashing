#define STRINGIFY2(X) #X
#define STRINGIFY(X) STRINGIFY2(X)

const uint64_t auth_bp                  =   0x7ffca4e76e10; // rbp value in auth
const uint64_t auth_cred_loc            =   0x7ffca4e76e00; // loc of cred 
const uint64_t auth_db_loc              =   0x7ffca4e76df8; // loc of db (local var of auth)
const uint64_t g_bp                     =   0x7ffca4e76e60; // rbp value in g
const uint64_t auth_cred                =   0x7ffca4e76d10; // value of cred (after alloca)
const uint64_t main_bp                  =   0x7ffca4e77550; // saved rbp value in mainloop
const uint64_t main_loop_return_addr_loc = 0x7ffca4e77518;
const uint64_t main_loop_return_addr    =   0x5613287a3ea9; // return address on the stack inside main loop
const uint64_t private_helper_addr      =   0x5613287a3f3a; // address of the private_helper
const uint64_t private_helper_addr2     =   0x5613287a3fa6; // address of the private_helper instruction to return to


const uint64_t auth_bp_cred_loc_dist    = auth_cred_loc - auth_bp;
const uint64_t auth_db_cred_dist        = auth_db_loc - auth_cred;
const uint64_t auth_bp_cred_dist        = auth_bp - auth_cred;
const uint64_t auth_main_bp_dist        = auth_bp - main_bp;
const uint64_t g_main_bp_dist		    = g_bp - main_bp;
const uint64_t g_bp_cred_dist		    = g_bp - auth_cred;
const uint64_t private_helper_distance  = private_helper_addr - main_loop_return_addr;
const uint64_t private_helper_distance2 = private_helper_addr2 - main_loop_return_addr;
const uint64_t main_loop_return_addr_dist = main_loop_return_addr_loc - main_bp;
