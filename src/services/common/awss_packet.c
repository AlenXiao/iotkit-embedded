/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include <stdint.h>
#include "os.h"
#include "passwd.h"
#include "awss_packet.h"
#include "awss_utils.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#ifdef WIFI_PROVISION_ENABLED
char *awss_build_sign_src(char *sign_src, int *sign_src_len)
{
    char *pk = NULL, *dev_name = NULL;
    int dev_name_len, pk_len, text_len;

    if (sign_src == NULL || sign_src_len == NULL) {
        goto build_sign_src_err;
    }

    pk = awss_zalloc(OS_PRODUCT_KEY_LEN + 1);
    dev_name = awss_zalloc(OS_DEVICE_NAME_LEN + 1);
    if (pk == NULL || dev_name == NULL) {
        goto build_sign_src_err;
    }

    os_product_get_key(pk);
    os_device_get_name(dev_name);

    pk_len = strlen(pk);
    dev_name_len = strlen(dev_name);

    text_len = RANDOM_MAX_LEN + dev_name_len + pk_len;
    if (*sign_src_len < text_len) {
        goto build_sign_src_err;
    }

    *sign_src_len = text_len;

    memcpy(sign_src, aes_random, RANDOM_MAX_LEN);
    memcpy(sign_src + RANDOM_MAX_LEN, dev_name, dev_name_len);
    memcpy(sign_src + RANDOM_MAX_LEN + dev_name_len, pk, pk_len);

    awss_free(pk);
    awss_free(dev_name);

    return sign_src;

build_sign_src_err:
    if (pk) {
        awss_free(pk);
    }
    if (dev_name) {
        awss_free(dev_name);
    }
    return NULL;
}
#endif

void produce_random(uint8_t *random, uint32_t len)
{
    int i = 0;
    int time = HAL_UptimeMs();
    HAL_Srandom(time);
    for (i = 0; i < len; i ++) {
        random[i] = HAL_Random(0xFF);
    }
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif
