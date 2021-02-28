#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

typedef struct rc4_state {
    int s_box_len;
    uint8_t* sbox;
    int i;
    int j;
    int x;
} rc4_state_t;
extern void rc4_init(rc4_state_t* state, const uint8_t *key, int keylen);
extern void rc4_crypt(rc4_state_t* state, const uint8_t *inbuf, uint8_t **outbuf, int buflen);