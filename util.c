#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "util.h"
#include <openssl/hmac.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

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
 * RC4 Init State.
 */
void rc4_init(rc4_state_t* state, const uint8_t *key, int keylen)
{
    if(state->x == 0) {
        state->i = 0;
        state->j = 0;
        state->s_box_len = 0x100;
        state->sbox = malloc(0x100);
        state->x = 1;
    }
    // Init sbox.
    int i = 0, index = 0, j = 0;
    uint8_t buf;
    while(i < state->s_box_len) {
        state->sbox[i] = (uint8_t)i;
        i++;
    }
    while(j < state->s_box_len) {
        index = ((index + state->sbox[j]) + key[j % keylen]) % state->s_box_len;
        buf = state->sbox[index];
        state->sbox[index] = (uint8_t)state->sbox[j];
        state->sbox[j] = (uint8_t)buf;
        j++;
    }
}
/*
 * RC4 Encrypt/Decrypt.
 */
void rc4_crypt(rc4_state_t* state, const uint8_t *inbuf, uint8_t **outbuf, int buflen)
{
    int idx = 0;
    uint8_t num, num2, num3;
    if(*outbuf) {
        free(*outbuf);
    }
    *outbuf = malloc(buflen);
    if (*outbuf) {  // do not forget to test for failed allocation
        while(idx != buflen) {
            state->i = (int)(state->i + 1) % 0x100;
            state->j = (int)(state->j + state->sbox[state->i]) % 0x100;
            num = (uint8_t)state->sbox[state->i];
            state->sbox[state->i] = (uint8_t)state->sbox[state->j];
            state->sbox[state->j] = (uint8_t)num;
            num2 = (uint8_t)inbuf[idx];
            num3 = (uint8_t)state->sbox[(state->sbox[state->i] + (uint8_t)state->sbox[state->j]) % 0x100];
            (*outbuf)[idx] = (uint8_t)(num2 ^ num3);
            idx++;
        }
    }
}

/* 
 * HMAC SHA1, Takes a cpu key and hashes the hmac_key, outputs digest.
 */
unsigned char* HMAC_SHA1(const char* cpukey, const unsigned char* hmac_key) {
    unsigned char* digest;
    digest = HMAC(EVP_sha1(), cpukey, 16, hmac_key, 16, NULL, NULL);
    return digest;
}