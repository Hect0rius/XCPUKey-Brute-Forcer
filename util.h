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
extern char* hex_to_char(const char* hex, int len);
extern unsigned char* HMAC_SHA1(char* cpukey, unsigned char* hmac_key);
#endif /* UTIL_H */

