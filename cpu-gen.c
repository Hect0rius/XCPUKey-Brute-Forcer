/*
 * Copyright Hect0r (c) 2016 - <sysop@staticpi.net>
 * XCPUKey-miner is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version. 
 *
 * XCPUKey-miner is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with XCPUKey-miner.  If not, see <http://www.gnu.org/licenses/>
 */

/* 
 * File:   cpu-gen.c
 * Author: Hect0r
 *
 * Created on 07 December 2016, 14:28
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include "util.h"
#include "crypto/enc/rc4.h"
#include "crypto/hash/hmac-sha1.h"

// Globals.
unsigned char *cpu_key, *serial_num;
uint8_t *kvheader;
uint8_t *hmac;

int debug = 0, mine = 1;
uint64_t total_hashes = 0;

typedef struct ModeOf {
	uint64_t Start;
	uint64_t Max;
	int ThreadNum;
} mode_t;

/*
 * Brute Thread. old fashioned brute force the cpukey.
 */
void* brute_thread(void* buf) {
    mode_t *tm = buf;
    printf("#%d Thread Started (Starting Index: %" PRIu64 ", Max Index: %" PRIu64 ", Mode: Increment)...\n", tm->ThreadNum, tm->Start, tm->Max);
    
	uint64_t key_buf[2] = { tm->Start, 0 };
    unsigned char key[16], *kp = key;
    unsigned char *hmac_buf, *hmac_key;
    
    // Init crypto support.
    rc4_state_t* rc4 = malloc(sizeof(rc4_state_t));
    // Outputs.
    uint8_t buf2[20];
    uint8_t* buf4 = malloc(16383);
   
    int kn = 0;
    
    // Copy hmac.
    hmac_buf = malloc(16);
    kn = 0;
    while(kn < 16) {
        hmac_buf[kn] = (unsigned char)hmac[kn];
        kn++;
    }
    
	
    while(mine > 0) {
        // Generate Hmac Key for decryption.
        hmac_key = HMAC_SHA1((char*)kp, (unsigned char*)hmac_buf);
        
        // Convert Hmac to uint8_t.
        kn = 0;
        while(kn < 16) {
            buf2[kn] = (uint8_t)hmac_key[kn];
            kn++;
        }
        
        // Decrypt kv_header and compare to know serial number.
        rc4_init(rc4, buf2, 16);
        rc4_crypt(rc4, kvheader, &buf4, 16368);
        
        // Compare The serial number.
        if(buf4[171] == (uint8_t)serial_num[11] &&
           buf4[170] == (uint8_t)serial_num[10] &&
           buf4[169] == (uint8_t)serial_num[9] &&
           buf4[168] == (uint8_t)serial_num[8] &&
           buf4[167] == (uint8_t)serial_num[7] &&
           buf4[166] == (uint8_t)serial_num[6] &&
           buf4[165] == (uint8_t)serial_num[5] &&
           buf4[164] == (uint8_t)serial_num[4] &&
           buf4[163] == (uint8_t)serial_num[3] &&
           buf4[162] == (uint8_t)serial_num[2] &&
           buf4[161] == (uint8_t)serial_num[1] &&
           buf4[160] == (uint8_t)serial_num[0]) {
            // Found CPU Key.
            printf("Found Key : ");
            
            kn = 0;
            while(kn < 16) {
                printf("%02X", kp[kn]);
                kn++;
            }
            printf("\n");
            mine = 0;
            pthread_exit(NULL);
        }
        else { // Get a new cpu key for next round.
			if(key_buf[0] == tm->Max) {
				if(key_buf[1] == UINT64_MAX) {
					mine = 0;
					printf("Mining Thread #%d is complete, no key found on this thread :(\n", tm->ThreadNum);
				}
				else {
					key_buf[0]++;
				}
			}
			else {
				key_buf[1]++;
			}
			
			kp[7] = (unsigned char)((key_buf[0] & 0xFF));
			kp[6] = (unsigned char)((key_buf[0] & 0x00FF) << 8);
			kp[5] = (unsigned char)((key_buf[0] & 0x0000FF) << 16);
			kp[4] = (unsigned char)((key_buf[0] & 0x000000FF) << 24);
			kp[3] = (unsigned char)((key_buf[0] & 0x00000000FF) << 32);
			kp[2] = (unsigned char)((key_buf[0] & 0x0000000000FF) << 40);
			kp[1] = (unsigned char)((key_buf[0] & 0x000000000000FF) << 48);
			kp[0] = (unsigned char)((key_buf[0] & 0x00000000000000FF) << 56);
			kp[15] = (unsigned char)((key_buf[1] & 0xFF));
			kp[14] = (unsigned char)((key_buf[1] & 0x00FF) << 8);
			kp[13] = (unsigned char)((key_buf[1] & 0x0000FF) << 16);
			kp[12] = (unsigned char)((key_buf[1] & 0x000000FF) << 24);
			kp[11] = (unsigned char)((key_buf[1] & 0x00000000FF) << 32);
			kp[10] = (unsigned char)((key_buf[1] & 0x0000000000FF) << 40);
			kp[9] = (unsigned char)((key_buf[1] & 0x000000000000FF) << 48);
			kp[8] = (unsigned char)((key_buf[1] & 0x00000000000000FF) << 56);
		}
        
        total_hashes++;
    }
    
    pthread_exit(NULL);
}

/*
 * Count Processors, taken from vanitygen by samr7.
 */
#if !defined(_WIN32)
int count_processors(void)
{
	FILE *fp;
	char buf[512];
	int count = 0;

	fp = fopen("/proc/cpuinfo", "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp)) {
		if (!strncmp(buf, "processor\t", 10))
			count += 1;
	}
	fclose(fp);
	return count;
}
#endif
/* 
 * Usage.
 */
void usage() {
    printf("XCPUKey-Brute-Forcer - 0.1c Beta by Hect0r\n"
           "Usage : cpu-gen [!keyvault_location] [!serial_number] [thread_count]\n"
           " NOTE : Each argument with a ! in it, needs to be set, without ! is optional.\n"
           "[keyvault_location] - The filepath to the ENCRYPTED keyvault.\n"
           "[serial_number] - Your console serial number, 12 numbers.\n"
           "[thread_count] - The number of cpu threads to use, default: num of cpu cores.\n");
}
/*
 * Main Entry point.
 */
 /*
 unsigned char* uint64_to_uchar(uint64_t input) {
	unsigned char *buf = malloc(sizeof(input));
	memcpy(buf, &input, sizeof(input));
	return buf;
}
uint64_t uchar_to_uint64(unsigned char *input, int start, bool reverse)
*/
int main(int argc, char** argv) {
    int nthreads = 0, t = 0, rc = 0;
    
    if(argc < 2) {
        usage();
        return EXIT_SUCCESS;
    }
    
    printf("XCPUKey-Brute-Forcer - 0.1e Beta by Hect0r\n");
    
    FILE *kv = fopen(argv[1], "r");
	if(!kv) {
		printf("Unable to open kv file...\n");
		return 1;
	}
    fseek(kv, 0, SEEK_SET);
    hmac = malloc(16);
    if(fread(hmac, 16, 1, kv) != 1) {
        fprintf(stderr, "Cannot read HMAC from KeyVault file...\n");
        return 1;
    }
    if(debug == 1) {
        printf("HMAC Seed : ");
        
        t = 0;
        while(t < 16) {
            printf("%02X", hmac[t]);
            t++;
        }
        printf("\n");
    }
    kvheader = malloc(16368);
    fseek(kv, 16, SEEK_SET);
    if(fread(kvheader, 16368, 1, kv) != 1) {
        fprintf(stderr, "Unable to read kv header from KeyVault...\n");
        return 1;
    }
    if(debug == 1) {
        printf("KV Header : ");
        
        t = 0;
        while(t < 16368) {
            printf("%02X", kvheader[t]);
            t++;
        }
        printf("\n");
    }
    
    if(argc >= 3) {
        t = 0;
        serial_num = malloc(12);
        if(debug == 1) { printf("Serial Number : "); }
        while(t < 12) {
            serial_num[t] = (unsigned char)argv[2][t];
            if(debug == 1) { printf("%02X", serial_num[t]); }
            t++;
        }
        if(debug == 1) { printf("\n"); }
    }
    else {
        fprintf(stderr, "Please provide your consoles serial number !");
        return 1;
    }
    if(argc >= 4) {
        nthreads = atoi(argv[3]);
        
        if(nthreads < 0 || nthreads == 0 || nthreads > 16) {
            nthreads = count_processors();
        }
    
    }

    if(debug == 1) {
        printf("KV Location %s\n"
               "Num Threads is %d\n",
                argv[1], nthreads);
    }
    
    pthread_t threads[nthreads];

    
    // Start Mining Threads.
    for(t = 0; t < nthreads; t++) {
		mode_t *buf = malloc(sizeof(mode_t));
		buf->ThreadNum = t;
		buf->Start = ((UINT64_MAX / nthreads) * t);
		buf->Max = buf->Start + (UINT64_MAX / nthreads); 
        rc = pthread_create(&threads[t], NULL, brute_thread, (void*)buf);
        if (rc){
            fprintf(stderr, "ERROR: could not create thread %d\n", t);
            exit(1);
        }
	}
    
    struct timeval last_upd;
    struct timeval tv_now;
    
    gettimeofday(&tv_now, NULL);
    gettimeofday(&last_upd, NULL);
    
    
    int hashes = 0, start = 0;
    while(mine == 1) {
        start = total_hashes;
        sleep(1);
        hashes = total_hashes - start;
        if((tv_now.tv_sec - last_upd.tv_sec) >= 5) {
            printf("[ HPS : %d h/ps - Total : %" PRIu64 " ]\n", hashes, total_hashes);
            gettimeofday(&last_upd, NULL);
        }
        
        gettimeofday(&tv_now, NULL);
    }
    pthread_exit(NULL);
    return (EXIT_SUCCESS);
}

