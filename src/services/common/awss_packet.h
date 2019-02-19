/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __AWSS_PACKET_H__
#define __AWSS_PACKET_H__

#define DEV_SIGN_SIZE                        (SHA1_DIGEST_SIZE)

void produce_random(uint8_t *random, uint32_t len);
char *awss_build_sign_src(char *sign_src, int *sign_src_len);

#endif
