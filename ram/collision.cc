// g++ -O3 collision.cc -o collision -lcrypto

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>

#include <map>

using namespace std;

static unsigned long     rand_m = 0;         /* multiplier                       */
static unsigned long     rand_ia = 0;        /* adder #1                         */
static unsigned long     rand_ib = 0;        /* adder #2                         */
static unsigned long     rand_irand = 0;     /* random value                     */

static void uuid_random_init (unsigned long seed)
{

    /*
     * optimal/recommended starting values according to the reference
     */
    static unsigned long   rand_m_init     = 971;
    static unsigned long   rand_ia_init    = 11113;
    static unsigned long   rand_ib_init    = 104322;
    static unsigned long   rand_irand_init = 4181;

    rand_m = rand_m_init;
    rand_ia = rand_ia_init;
    rand_ib = rand_ib_init;
    rand_irand = rand_irand_init;

    rand_irand += seed;
}

static unsigned long uuid_random (void)
{
    rand_m += 7;
    rand_ia += 1907;
    rand_ib += 73939;

    if (rand_m >= 9973) rand_m -= 9871;
    if (rand_ia >= 99991) rand_ia -= 89989;
    if (rand_ib >= 224729) rand_ib -= 96233;

    rand_irand = (rand_irand * rand_m) + rand_ia + rand_ib;

    return rand_irand;
}

static void transform_string (unsigned long n, char* buf)
{
    buf[0] = 'a' + ((n  >> 60) & 0xf);
    buf[1] = 'a' + ((n  >> 56) & 0xf);
    buf[2] = 'a' + ((n  >> 52) & 0xf);
    buf[3] = 'a' + ((n  >> 48) & 0xf);
    buf[4] = 'a' + ((n  >> 44) & 0xf);
    buf[5] = 'a' + ((n  >> 40) & 0xf);
    buf[6] = 'a' + ((n  >> 36) & 0xf);
    buf[7] = 'a' + ((n  >> 32) & 0xf);
    buf[8] = 'a' + ((n  >> 28) & 0xf);
    buf[9] = 'a' + ((n  >> 24) & 0xf);
    buf[10] = 'a' + ((n  >> 20) & 0xf);
    buf[11] = 'a' + ((n  >> 16) & 0xf);
    buf[12] = 'a' + ((n  >> 12) & 0xf);
    buf[13] = 'a' + ((n  >> 8) & 0xf);
    buf[14] = 'a' + ((n  >> 4) & 0xf);
    buf[15] = 'a' + (n & 0xf);
}

static void unique_rand_string (char* buf)
{
    unsigned long n = uuid_random();
    
    transform_string(n, buf);
}


static void report_collision (size_t a, size_t b, unsigned long seed)
{
    uuid_random_init(seed); //reinit
    
    int c = 0;
    size_t i;
    for(i = 0; c < 2; ++i) {
        unsigned long n = uuid_random();
        
        if(i == a || i == b) {
            char data[17];
            unsigned char md[SHA_DIGEST_LENGTH];
            
            transform_string(n, data);
            data[16] = 0;
            printf("data: %16s\n", data);
            
            SHA_CTX context;
            SHA1_Init(&context);
            
            SHA1_Update(&context, data, 16);
            
            SHA1_Final(md, &context);
            
            printf("hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n", md[0], md[1], md[2], md[3], md[4], md[5], md[6], md[7], md[8], md[9], md[10], md[11], md[12], md[13], md[14], md[15], md[16], md[17], md[18], md[19]);
            
            ++c;
        }
    }
}


#define HASH_LEN 6
// 2**(HASH_LEN*4) at least
#define ATTEMPTS (2*16777216)
#define OBJ_LEN 3

int main (int argc, char **argv)
{
    int r;
    size_t i;
    unsigned long seed = time(0);
    printf("seed: %lu\n", seed);
    
    uuid_random_init(seed);

    if(argc > 1) {
        int init = atoi(argv[1]);
        
        for(i = 0; i < init; ++i)
            uuid_random();
        
        printf("initialization completed.\n");
    }
    
    map<string, string> ht;
    
    printf("\n");
    
    for(i = 0; i < ATTEMPTS; ++i) {
    
        if((i >> 14) << 14 == i)
            printf("\033[A\33[2KT\rprogress: %lf %%  [%lu of %lu]\n", i*100.0/ATTEMPTS, i, ATTEMPTS);
    
        char data[16];
        unsigned char md[SHA_DIGEST_LENGTH];
        
        unique_rand_string(data);
        
        SHA_CTX context;
        SHA1_Init(&context);
        
        SHA1_Update(&context, data, 16);
        
        SHA1_Final(md, &context);
        
        char idx[OBJ_LEN];
        idx[0] = (char)i;
        idx[1] = (char)(i >> 8);
        idx[2] = (char)(i >> 16);
        //idx[3] = (char)(i >> 24);
        
        md[SHA_DIGEST_LENGTH-HASH_LEN] = md[SHA_DIGEST_LENGTH-HASH_LEN] & 0xf;
        
        string key((char*)&md[SHA_DIGEST_LENGTH-HASH_LEN], HASH_LEN);
        
        if(ht.find(key) != ht.end()) {
            printf("\nCOLLISION!!!\n");
            string g = ht[key];
            
            unsigned int o = 0;
            o |= (unsigned char)g[0];
            o |= (unsigned char)g[1] << 8;
            o |= (unsigned char)g[2] << 16;
            //o |= (unsigned char)g[3] << 24;
            
            printf("idexes: %lu   %u\n", i, o);
            report_collision(i, o, seed);
            
            return 0;
        }
        
        ht[key] = string(idx, OBJ_LEN);
    }
}
