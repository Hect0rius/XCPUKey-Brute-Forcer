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
 * File:   cpu-miner.c
 * Author: Hect0r
 *
 * Created on 07 December 2016, 14:28
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <string.h>
#include <pthread.h>
#include <getopt.h>
#include <time.h>
#include <curl/curl.h>
#include <json/json.h>
#include <inttypes.h>
#include <unistd.h>

typedef struct server_work_data {
    const uint8_t* encrypted_data;
    const unsigned char* hmac;
    double reward;
    
} server_work_data_t;

struct url_data {
    size_t size;
    char* data;
};


// Globals.
server_work_data_t work_data[100000];
const char* reward_addr; // The miners bitcoin address.
int interval = 1024; // The number of seconds per workdata refresh.
const char* server_url = "http://xck.pkx.pw/";
int debug = 1, mine = 1, worksize = 1, end_miner = 0, good_shares = 0,
    bad_shares = 0, workdata_size = 0, wait = 0;
uint64_t total_hashes = 0;

struct timeval tv_started;

/* Curl Routines */
/*
 * Writes the data from curl data reader.
 * With thanks too : http://stackoverflow.com/a/13906020
 */
size_t write_data(void *ptr, size_t size, size_t nmemb, struct url_data *data) {
    size_t index = data->size;
    size_t n = (size * nmemb);
    char* tmp;

    data->size += (size * nmemb);
    tmp = realloc(data->data, data->size + 1); /* +1 for '\0' */

    if(tmp) {
        data->data = tmp;
    } else {
        if(data->data) {
            free(data->data);
        }
        fprintf(stderr, "Failed to allocate memory.\n");
        return 0;
    }

    memcpy((data->data + index), ptr, n);
    data->data[data->size] = '\0';

    return size * nmemb;
}
/*
 * Handles a url connect via curl and gets the data response.
 * With thanks too : http://stackoverflow.com/a/13906020
 */
char *handle_url(char* url) {
    CURL *curl;

    struct url_data data;
    data.size = 0;
    data.data = malloc(4096); /* reasonable size initial buffer */
    if(NULL == data.data) {
        fprintf(stderr, "Failed to allocate memory.\n");
        return NULL;
    }

    data.data[0] = '\0';

    CURLcode res;

    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &data);
        res = curl_easy_perform(curl);
        if(res != CURLE_OK) {
                fprintf(stderr, "curl_easy_perform() failed: %s\n",  
                        curl_easy_strerror(res));
        }

        curl_easy_cleanup(curl);

    }
    return data.data;
}

/* Crypto and Hashing Routines */
// RC4 was written from AccountRC4.cs in RGBuild by RGLoader,
// Customised for 8 bytes of data.
typedef struct rc4_state {
    int s_box_len;
    uint8_t* sbox;
    int i;
    int j;
} rc4_state_t;
/*
 * RC4 Init State.
 */
void rc4_init(rc4_state_t* state, const uint8_t *key, int keylen)
{
    state->i = 0;
    state->j = 0;
    state->s_box_len = 0x100;
    state->sbox = malloc(0x100);
    
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
    unsigned char* digest = malloc(20);
    
    digest = HMAC(EVP_sha1(), cpukey, 16, hmac_key, 16, NULL, NULL);
    
    return digest;
}

/*
 * Update Work Data.
 */
/*void update_work_data() {
    
    char* data = handle_url("http://xcp.pkx.pw/mine?method=get_work");
    
    if(strlen(data) > 0) {
        const char* buf;
        int x = 0, w = 0;
        json_object* jobj = json_tokener_parse(data);
        json_object_object_foreach(jobj, key, val) {
            // All arrays.
            const char* work = json_object_get_string(val);
            
            json_object* jobj2 = json_tokener_parse(work);
            
            json_object_object_foreach(jobj2, key2, val2) {
                server_work_data_t wd;
                
                if(strcmp("data", (const char*)key2) == 0) {
                    buf = json_object_get_string(val2);
                    
                    x = 0;
                    while(x < 8) {
                        //wd.encrypted_data[x] = (uint8_t)buf[x];
                        x++;
                    }
                }
                else if(strcmp("hmac", (const char*)key2) == 0) {
                    buf = json_object_get_string(val2);
                    
                    x = 0;
                    while(x < 16) {
                        //(*wd).hmac[x] = (uint8_t)buf[x];
                        x++;
                    }
                }
                work_data[w] = wd;
            }
            
        }
    }
    else {
        printf("Unable to get mining data, aborting...");
        exit(1);
    }
}*/
/*
 * Mining Thread.
 */
void* miner_thread(void* id) {
    long tid = (long)id;
    
    printf("Mining Thread Started : #%ld\n", tid);
    
    char key[16], *kp = key;
    rc4_state_t* rc4 = malloc(sizeof(rc4_state_t));
    unsigned char* cpu_key;
    const unsigned char* hmac_buf;
    uint8_t* outdata;
    MD5_CTX mdcontext;
    
    MD5_Init(&mdcontext);
    int kn = 0, wdn = 0;
    // Allocate space.
    cpu_key = malloc(16 * worksize);
    start:
    
    // Fill Key with random bytes.
    kn = 0;
    while(kn < 16) {
        kp[kn] = (char)rand();
        kn++;
    }
    while(mine > 0 && end_miner == 0) {
        // Hash Previous CPU Key
        MD5_Update(&mdcontext, key, 16);
        MD5_Final(cpu_key, &mdcontext);
        
        // Loop through each work item.
        while(wdn < workdata_size) {
            hmac_buf = HMAC_SHA1((const char*)&kp, work_data[wdn].hmac);
            rc4_init(rc4, hmac_buf, 0x10);
            
            
            rc4_crypt(rc4, work_data[wdn].encrypted_data, &outdata, 8);
            
            // Xbox 360 || 58626F7820333630
            if(outdata[0] == 0x58 &&
               outdata[1] == 0x62 &&
               outdata[2] == 0x6f &&
               outdata[3] == 0x78 &&
               outdata[4] == 0x20 &&
               outdata[5] == 0x33 &&
               outdata[6] == 0x36 &&
               outdata[7] == 0x30) {
                // Submit Share.
                printf("Found CPU Key :)\n");
                
                // Output CPU Key Found.
                kn = 0;
                while(kn < 16) {
                    printf("%02X", cpu_key[kn]);
                    kn++;
                }
                printf("\n");
            }
            
            wdn++;
        }
        total_hashes++;
    }
    
    if(end_miner == 0) {
        while(wait == 1) {
            // Procrastinate :)
        }
        
        if(end_miner == 0) {
            goto start;
        }
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
    printf("XCPUKey-Miner - 0.1a Beta by Hect0r\n"
           "Usage : cpu-miner [reward_btc_address] [num_threads] [work_refresh_seconds] [worksize]\n"
           "[reward_btc_address] - Your bitcoin reward address.\n"
           "[num_threads] - The number of cpu threads to use when mining.\n"
           "[work_refresh_seconds] - The number of seconds to wait before refreshing workdata from server.\n");
}
/*
 * Main Entry point.
 */
int main(int argc, char** argv) {

    int nthreads = 0, t = 0, rc = 0;
    
    if(argc < 2) {
        usage();
        return EXIT_SUCCESS;
    }
    
    reward_addr = argv[1];
    nthreads = atoi(argv[2]);
    interval = atoi(argv[3]);
    worksize = atoi(argv[4]);
    
    // Correct number of threads, if needed.
    if(nthreads < 0 || nthreads == 0) {
        nthreads = count_processors();
    }
    
    // Correct work refresh interval, if needed.
    if(interval < 30) {
        interval = 30;
    }
    
    if(strlen(reward_addr) != 34 || reward_addr[0] != '1') {
        fprintf(stderr, "Invalid reward address '%s', please supply a valid bitcoin address.", reward_addr);
        return 1;
    }
    
    if(debug == 1) {
        printf("Reward address is %s\n"
               "Num Threads is %d\n"
               "Work Refresh every %d seconds.\n", 
                reward_addr, nthreads, interval);
    }
    
    
    pthread_t threads[nthreads];

    
    // Start Mining Threads.
    for(t = 0; t < nthreads; t++) {
        rc = pthread_create(&threads[t], NULL, miner_thread, (void *)t);
        if (rc){
            fprintf(stderr, "ERROR: could not create thread %d\n", t);
            exit(1);
        }
    }
    
    struct timeval last_upd;
    struct timeval last_work_upd;
    struct timeval now;
    
    gettimeofday(&now, NULL);
    gettimeofday(&last_upd, NULL);
    gettimeofday(&last_work_upd, NULL);
    return (EXIT_SUCCESS);
}

