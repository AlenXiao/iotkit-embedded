/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdlib.h>
#include "aws_lib.h"
#include "zconfig_lib.h"
#include "zconfig_utils.h"
#include "awss_enrollee.h"
#include "awss_packet.h"
#include "awss_statis.h"
#include "awss_event.h"
#include "awss_main.h"
#include "passwd.h"
#include "awss.h"
#include "os.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

char awss_finished = 2;
char awss_stop_connecting = 0;

int __awss_start(void)
{
    char ssid[OS_MAX_SSID_LEN + 1] = {0}, passwd[OS_MAX_PASSWD_LEN + 1] = {0};
    enum AWSS_AUTH_TYPE auth = AWSS_AUTH_TYPE_INVALID;
    enum AWSS_ENC_TYPE encry = AWSS_ENC_TYPE_INVALID;
    uint8_t bssid[OS_ETH_ALEN] = {0};
    uint8_t channel = 0;
    int ret;

    awss_stop_connecting = 0;
    awss_finished = 0;
    /* these params is useless, keep it for compatible reason */
    aws_start(NULL, NULL, NULL, NULL);

    ret = aws_get_ssid_passwd(&ssid[0], &passwd[0], &bssid[0],
            (char *)&auth, (char *)&encry, &channel);
    if (!ret)
        awss_warn("awss timeout!");

    if (awss_stop_connecting) {
        awss_finished = 1;
        return -1;
    }

    aws_destroy();

    do {
        if (awss_stop_connecting || strlen(ssid) == 0) {
            break;
        }
        {
            awss_event_post(AWSS_CONNECT_ROUTER);
            AWSS_UPDATE_STATIS(AWSS_STATIS_CONN_ROUTER_IDX, AWSS_STATIS_TYPE_TIME_START);
        }

        ret = os_awss_connect_ap(WLAN_CONNECTION_TIMEOUT_MS, ssid, passwd,
                                 auth, encry, bssid, channel);
        awss_trace("awss connect ssid:%s %s", ssid, ret == 0 ? "success" : "fail");
        if (!ret) {
            awss_event_post(AWSS_GOT_IP);

            {
                AWSS_UPDATE_STATIS(AWSS_STATIS_CONN_ROUTER_IDX, AWSS_STATIS_TYPE_TIME_SUC);
                produce_random(aes_random, sizeof(aes_random));
            }
        } else {
            {
                awss_event_post(AWSS_CONNECT_ROUTER_FAIL);
#ifndef AWSS_DISABLE_ENROLLEE
                awss_enrollee_connect_router_fail(0);
#endif
            }
        }
    } while (0);

    AWSS_DISP_STATIS();
    awss_finished = 1;
    return 0;
}

int __awss_stop(void)
{
    awss_stop_connecting = 1;
    aws_destroy();
#ifndef AWSS_DISABLE_REGISTRAR
    awss_registrar_deinit();
#endif

    while (1) {
        if (awss_finished) break;
        awss_msleep(300);
    }
    aws_release_mutex();
    awss_finished = 2;
    return 0;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif
