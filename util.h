/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/* 
 * File:   util.h
 * Author: Hect0r
 *
 * Created on 09 December 2016, 13:53
 */

#ifndef UTIL_H
#define UTIL_H

#ifdef __cplusplus
extern "C" {
#endif

    extern char* hex_to_char(const char* hex, int len);
    /* Crypto and Hashing Routines */
    // RC4 was written from AccountRC4.cs in RGBuild by RGLoader,
    // Customised for 8 bytes of data.
    typedef struct rc4_state {
        int s_box_len;
        uint8_t* sbox;
        int i;
        int j;
        int x;
    } rc4_state_t;
    extern void rc4_init(rc4_state_t* state, const uint8_t *key, int keylen);
    extern void rc4_crypt(rc4_state_t* state, const uint8_t *inbuf, uint8_t **outbuf, int buflen);
    extern unsigned char* HMAC_SHA1(const char* cpukey, const unsigned char* hmac_key);
    
#ifdef __cplusplus
}
#endif

#endif /* UTIL_H */

