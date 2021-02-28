#include "rc4.h"

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