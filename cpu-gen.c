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
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include "util.h"

// Globals.
unsigned char *cpu_key, *serial_num;
uint8_t *kvheader;
uint8_t *hmac;

int debug = 0, mine = 1, at = 0;
uint64_t total_hashes = 0;

/*
 * Brute Thread. old fashioned brute force the cpukey.
 */
void* brute_thread(void* id) {
    long tid = (long)id;
    
    printf("Mining Thread Started : #%ld\n", tid);
    
    char key[16], *kp = key;
    unsigned char *hmac_buf, *hmac_key;
    
    // Init Hashing Support.
    MD5_CTX mdcontext;
    
    // Init crypto support.
    rc4_state_t* rc4 = malloc(sizeof(rc4_state_t));
    // Outputs.
    uint8_t buf2[20];
    uint8_t* buf4 = malloc(182);
   
    int kn = 0;
    
    // Copy hmac.
    hmac_buf = malloc(16);
    kn = 0;
    while(kn < 16) {
        hmac_buf[kn] = (unsigned char)hmac[kn];
        kn++;
    }
    
    // Set key based on algo.
    switch(at) {
        case 1: // Random - Hash
        case 2: // Random - Increment.
            kn = 0;
            while(kn < 16) {
                kp[kn] = (char)rand() % 100 / 2;
                kn++;
            }
            break;
        case 3: // Start Seed - Hash
        case 4: // Start Seed - Increment
            
            kn = 0;
            while(kn < 16) {
                kp[kn] = (char)cpu_key[kn];
                kn++;
            }
            // Randomise some of the seed.
            cpu_key[tid]++; // To make sure we're not mining the same thing on each thread.
            break;
            
    }
    
    MD5_Init(&mdcontext);
    MD5_Update(&mdcontext, key, 16);
    MD5_Final(cpu_key, &mdcontext);
    while(mine > 0) {
        // Generate Hmac Key for decryption.
        hmac_key = HMAC_SHA1((const char*)kp, (const unsigned char*)hmac_buf);
        
        // Convert Hmac to uint8_t.
        kn = 0;
        while(kn < 16) {
            buf2[kn] = (uint8_t)hmac_key[kn];
            kn++;
        }
        
        // Decrypt kv_header and compare to know serial number.
        rc4_init(rc4, buf2, 16);
        rc4_crypt(rc4, kvheader, &buf4, 182);
        
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
            switch(at) {
                case 1:
                case 3:
                    MD5_Init(&mdcontext);
                    MD5_Update(&mdcontext, (unsigned char *)kp, 16);
                    MD5_Final((unsigned char*)kp, &mdcontext);
                    break;
                case 2:
                case 4:
                    if(kp[15] == 255) {
                        kp[15] = 0;
                        if(kp[14] == 255) {
                            kp[14] = 0;
                            if(kp[13] == 255) {
                                kp[13] = 0;
                                if(kp[12] == 255) {
                                    kp[12] = 0;
                                    if(kp[11] == 255) {
                                        kp[11] = 0;
                                        if(kp[10] == 255) {
                                            kp[10] = 0;
                                            if(kp[9] == 255) {
                                                kp[9] = 0;
                                                if(kp[8] == 255) {
                                                    kp[8] = 0;
                                                    if(kp[7] == 255) {
                                                        kp[7] = 0;
                                                        if(kp[6] == 255) {
                                                            kp[6] = 0;
                                                            if(kp[5] == 255) {
                                                                kp[5] = 0;
                                                                if(kp[4] == 255) {
                                                                    kp[4] = 0;
                                                                    if(kp[3] == 255) {
                                                                        kp[3] = 0;
                                                                        if(kp[2] == 255) {
                                                                            kp[2] = 0;
                                                                            if(kp[1] == 255) {
                                                                                kp[1] = 0;
                                                                                if(kp[0] == 255) {
                                                                                    kp[0] = 0;
                                                                                }
                                                                                else {
                                                                                    kp[0]++;
                                                                                }
                                                                            }
                                                                            else {
                                                                                kp[1]++;
                                                                            }
                                                                        }
                                                                        else {
                                                                            kp[2]++;
                                                                        }
                                                                    }
                                                                    else {
                                                                        kp[3]++;
                                                                    }
                                                                }
                                                                else {
                                                                    kp[4]++;
                                                                }
                                                            }
                                                            else {
                                                                kp[5]++;
                                                            }
                                                        }
                                                        else {
                                                            kp[6]++;
                                                        }
                                                    }
                                                    else {
                                                        kp[7]++;
                                                    }
                                                }
                                                else {
                                                    kp[8]++;
                                                }
                                            }
                                            else {
                                                kp[9]++;
                                            }
                                        }
                                        else {
                                            kp[10]++;
                                        }
                                    }
                                    else {
                                        kp[11]++;
                                    }
                                }
                                else {
                                    kp[12]++;
                                }
                            }
                            else {
                                kp[13]++;
                            }
                        }
                        else {
                            kp[14]++;
                        }
                    }
                    else {
                        kp[15]++;
                    }
                    break;
            }
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
           "Usage : cpu-gen [!keyvault_location] [!algo_type] [!serial_number] [thread_count] [start_seed]\n"
           " NOTE : Each argument with a ! in it, needs to be set, without ! is optional.\n"
           "[keyvault_location] - The filepath to the ENCRYPTED keyvault.\n"
           "[algo_type] - The also to use, can be 1, 2, 3, 4 (See Read Me).\n"
           "[serial_number] - Your console serial number, 12 numbers.\n"
           "[thread_count] - The number of cpu threads to use, default: num of cpu cores.\n"
           "[starting_seed] - The seed to start with, must be 16 bytes long.\n");
}
/*
 * Main Entry point.
 */
int main(int argc, char** argv) {

    int nthreads = 0, t = 0, rc = 0;
    const char* kv_location;
    
    if(argc < 2) {
        usage();
        return EXIT_SUCCESS;
    }
    
    kv_location = argv[1];
    
    //FILE* kv = file_handle(kv_location, "r");
    FILE *kv = fopen(kv_location, "r");
    fseek(kv, 0, SEEK_SET);
    hmac = malloc(16);
    if(fread(hmac, 16 + 1, 1, kv) != 1) {
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
    kvheader = malloc(182);
    fseek(kv, 16, SEEK_SET);
    if(fread(kvheader, 182 + 1, 1, kv) != 1) {
        fprintf(stderr, "Unable to read kv header from KeyVault...\n");
        return 1;
    }
    if(debug == 1) {
        printf("KV Header : ");
        
        t = 0;
        while(t < 182) {
            printf("%02X", kvheader[t]);
            t++;
        }
        printf("\n");
    }
    
    at = atoi(argv[2]);
    
    if(argc >= 4) {
        t = 0;
        serial_num = malloc(12);
        if(debug == 1) { printf("Serial Number : "); }
        while(t < 12) {
            serial_num[t] = (unsigned char)argv[3][t];
            if(debug == 1) { printf("%02X", serial_num[t]); }
            t++;
        }
        if(debug == 1) { printf("\n"); }
    }
    else {
        fprintf(stderr, "Please provide your consoles serial number !");
        return 1;
    }
    if(argc >= 5) {
        nthreads = atoi(argv[4]);
        
        if(nthreads < 0 || nthreads == 0) {
            nthreads = count_processors();
        }
    
    }
    
    if(argc >= 6) {
        if(strlen(argv[5]) != 32) {
            fprintf(stderr, "The starting seed is invalid, minimum/maximum : 16 bytes\n");
            return 1;
        }
        
        t = 0;
        cpu_key = malloc(16);
        char* buf = hex_to_char(argv[5], 32);
        if(debug == 1) { printf("Start Seed : "); }
        while(t < 16) {
            cpu_key[t] = (unsigned char)buf[t];
            if(debug == 1) { printf("%02X", cpu_key[t]); }
            t++;
        }
        if(debug == 1) { printf("\n"); }
    }
    else if(argc < 6 && (at == 3 || at == 4)) {
        fprintf(stderr, "Invalid starting seed provided...\n");
        return 1;
    }

    if(debug == 1) {
        printf("KV Location %s\n"
               "Num Threads is %d\n"
               "Algo type : %d.\n", 
                kv_location, nthreads, at);
    }
    
    pthread_t threads[nthreads];

    
    // Start Mining Threads.
    for(t = 0; t < nthreads; t++) {
        rc = pthread_create(&threads[t], NULL, brute_thread, (void *)t);
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
        if(tv_now.tv_sec - last_upd.tv_sec >= 5) {
            printf("[ HPS : %d h/ps - Total : %" PRIu64 " ]\n", hashes, total_hashes);
            gettimeofday(&last_upd, NULL);
        }
        
        gettimeofday(&tv_now, NULL);
    }
    pthread_exit(NULL);
    return (EXIT_SUCCESS);
}

