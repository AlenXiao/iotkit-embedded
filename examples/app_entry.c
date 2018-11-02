/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "iot_export.h"
#include "app_entry.h"


#define PRODUCT_KEY     "a1X2bEnP82z"
#define PRODUCT_SECRET  "7jluWm1zql7bt8qK"
#define DEVICE_NAME     "ilop-dev-bind-test"
#define DEVICE_SECRET   "55hC6DOvX2OFU0yviK2MICyO5WVRJkJS"

int main(int argc, char **argv)
{
    app_main_paras_t paras;
    paras.argc = argc;
    paras.argv = argv; 
    
    HAL_SetProductKey(PRODUCT_KEY);
    HAL_SetProductSecret(PRODUCT_SECRET);
    HAL_SetDeviceName(DEVICE_NAME);
    HAL_SetDeviceSecret(DEVICE_SECRET);

    awss_config_press();
    awss_start();
    linkkit_main((void *)&paras);
    return 0;
}
