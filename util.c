#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "util.h"
#include "crypto/hash/hmac-sha1.h"
#include "crypto/enc/rc4.h"
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

char* hex_to_char(const char* hex, int len) {
    char *_a = malloc(len / 2);
    int num = 0;
    unsigned _b;
    while(num < len) {
        sscanf(&hex[num], "%02X", &_b);
        _a[num/2] = _b;
        num += 2;
    }
    
    return _a;
}


/* 
 * HMAC SHA1, Takes a cpu key and hashes the hmac_key, outputs digest.
 */
unsigned char* HMAC_SHA1(char* cpukey, unsigned char* hmac_key) {
    unsigned char* digest = malloc(16);
    //digest = HMAC(EVP_sha1(), cpukey, 16, hmac_key, 16, NULL, NULL);
    HMAC_SHA1_Hash(cpukey, hmac_key, digest, 16);
	return digest;
}