/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdint.h>
#include <string.h>

#include "iot_import.h"
#include "os.h"
#include "awss_log.h"
#include "awss_packet.h"
#include "awss_statis.h"

#ifdef AWSS_SUPPORT_STATIS

#define DROUTE_START    g_awss_statis.droute.conn_router_start
#define DROUTE_END      g_awss_statis.droute.conn_router_end
#define DROUTE_CNT      g_awss_statis.droute.conn_router_cnt
#define DROUTE_SUC      g_awss_statis.droute.conn_router_suc
#define DROUTE_TMIN     g_awss_statis.droute.conn_router_time_min
#define DROUTE_TMAX     g_awss_statis.droute.conn_router_time_max
#define DROUTE_TMEAN    g_awss_statis.droute.conn_router_time_mean

#ifdef  AWSS_SUPPORT_SMARTCONFIG
#ifdef  AWSS_SUPPORT_SMARTCONFIG_WPS
#define WPS_CNT         g_awss_statis.wps.wps_parse_cnt
#define WPS_CRC_ERR     g_awss_statis.wps.wps_parse_crc_err
#define WPS_PW_ERR      g_awss_statis.wps.wps_parse_passwd_err
#define WPS_SUC         g_awss_statis.wps.wps_parse_suc
#endif
#define SM_CNT          g_awss_statis.sm.sm_parse_cnt
#define SM_CRC_ERR      g_awss_statis.sm.sm_parse_crc_err
#define SM_PW_ERR       g_awss_statis.sm.sm_parse_passwd_err
#define SM_SUC          g_awss_statis.sm.sm_parse_suc
#define SM_START        g_awss_statis.sm.sm_parse_start
#define SM_END          g_awss_statis.sm.sm_parse_end
#define SM_TMIN         g_awss_statis.sm.sm_time_min
#define SM_TMAX         g_awss_statis.sm.sm_time_max
#define SM_TMEAN        g_awss_statis.sm.sm_time_mean
#endif

#ifndef AWSS_DISABLE_ENROLLEE
#define ZC_CNT          g_awss_statis.zconfig.zc_cnt
#define ZC_SUC          g_awss_statis.zconfig.zc_suc
#define ZC_PW_ERR       g_awss_statis.zconfig.zc_passwd_err
#endif

static void *awss_statis_mutex = NULL;
static struct awss_statis_t g_awss_statis = {0};

void awss_disp_statis()
{
    if (awss_statis_mutex)
        HAL_MutexLock(awss_statis_mutex);

    awss_debug("--------------------------------AWSS STATIS-----------------------------------");
    awss_debug("name\t\tmax\tmin\tmean\tcnt\tsuc\tcrc-err\tpasswd-err");
    awss_debug("Router      \t%u\t%u\t%u\t%u\t%u\t%u\t%u\t",
            DROUTE_TMAX, DROUTE_TMIN, DROUTE_TMEAN, DROUTE_CNT, DROUTE_SUC, 0, 0);
#ifdef AWSS_SUPPORT_SMARTCONFIG
    awss_debug("SM          \t%u\t%u\t%u\t%u\t%u\t%u\t%u\t",
            SM_TMAX, SM_TMIN, SM_TMEAN, SM_CNT, SM_SUC, SM_CRC_ERR, SM_PW_ERR);
#ifdef  AWSS_SUPPORT_SMARTCONFIG_WPS
    awss_debug("WPS         \t%u\t%u\t%u\t%u\t%u\t%u\t%u\t",
            0, 0, 0, WPS_CNT, WPS_SUC, WPS_CRC_ERR, WPS_PW_ERR);
#endif
#endif
#ifndef AWSS_DISABLE_ENROLLEE
    awss_debug("Zconfig       \t%u\t%u\t%u\t%u\t%u\t%u\t%u\t",
            0, 0, 0, ZC_CNT, ZC_SUC, 0, ZC_PW_ERR);
#endif
    awss_debug("------------------------------------------------------------------------------");

    if (awss_statis_mutex)
        HAL_MutexUnlock(awss_statis_mutex);
}

void awss_clear_statis()
{
    if (awss_statis_mutex)
        HAL_MutexLock(awss_statis_mutex);

    memset(&g_awss_statis, 0, sizeof(g_awss_statis));

    awss_statis_trace_id = 0;
    awss_statis_report_id = 0;

    if (awss_statis_mutex) {
        HAL_MutexUnlock(awss_statis_mutex);
        HAL_MutexDestroy(awss_statis_mutex);
    }
    awss_statis_mutex = NULL;
}

void awss_update_statis(int awss_statis_idx, int type)
{
    uint32_t time = HAL_UptimeMs();

    if (awss_statis_mutex == NULL) {
        awss_statis_mutex = HAL_MutexCreate();
        if (awss_statis_mutex == NULL) {
            awss_debug("a-statis am fail\n");
            return;
        }
    }

    HAL_MutexLock(awss_statis_mutex);

    if (type == AWSS_STATIS_TYPE_TIME_START)
        awss_statis_trace_id ++;

    switch (awss_statis_idx) {
        case AWSS_STATIS_CONN_ROUTER_IDX:
            switch (type) {
                case AWSS_STATIS_TYPE_TIME_START:
                    DROUTE_CNT ++;
                    DROUTE_START = time;
                    break;
                case AWSS_STATIS_TYPE_TIME_SUC:
                    DROUTE_SUC ++;
                    DROUTE_END = time;
                    time = (uint32_t)(DROUTE_END - DROUTE_START);
                    if (DROUTE_SUC > 0) {
                        DROUTE_TMEAN = (DROUTE_TMEAN + time) / (DROUTE_SUC);
                    } else {
                        DROUTE_TMEAN = time;
                        DROUTE_SUC = 1;
                    }
                    if (DROUTE_TMIN == 0 || DROUTE_TMIN > time)
                        DROUTE_TMIN = time;
                    if (DROUTE_TMAX == 0 || DROUTE_TMAX < time)
                        DROUTE_TMAX = time;
                    break;
                default:
                    break;
            }
            break;
#ifdef AWSS_SUPPORT_SMARTCONFIG
#ifdef AWSS_SUPPORT_SMARTCONFIG_WPS
        case AWSS_STATIS_WPS_IDX:
            switch (type) {
                case AWSS_STATIS_TYPE_TIME_START:
                    WPS_CNT ++;
                    break;
                case AWSS_STATIS_TYPE_TIME_SUC:
                    WPS_SUC ++;
                    break;
                case AWSS_STATIS_TYPE_PASSWD_ERR:
                    WPS_PW_ERR ++;
                    break;
                case AWSS_STATIS_TYPE_CRC_ERR:
                    WPS_CRC_ERR ++;
                    break;
                default:
                    break;
            }
            break;
#endif
        case AWSS_STATIS_SM_IDX:
            switch (type) {
                case AWSS_STATIS_TYPE_TIME_START:
                    SM_CNT ++;
                    SM_START = time;
                    break;
                case AWSS_STATIS_TYPE_TIME_SUC:
                    SM_SUC ++;
                    SM_END = time;
                    time = (uint32_t)(SM_END - SM_START);
                    if (SM_SUC > 0) {
                        SM_TMEAN = (SM_TMEAN + time) / (SM_SUC);
                    } else {
                        SM_TMEAN = time;
                        SM_SUC = 1;
                    }

                    if (SM_TMIN == 0 || SM_TMIN > time)
                        SM_TMIN = time;
                    if (SM_TMAX == 0 || SM_TMAX < time)
                        SM_TMAX = time;
                    break;
                case AWSS_STATIS_TYPE_PASSWD_ERR:
                    SM_PW_ERR ++;
                    break;
                case AWSS_STATIS_TYPE_CRC_ERR:
                    SM_CRC_ERR ++;
                    break;
                default:
                    break;
            }
            break;
#endif
#ifndef AWSS_DISABLE_ENROLLEE
        case AWSS_STATIS_ZCONFIG_IDX:
            switch (type) {
                case AWSS_STATIS_TYPE_TIME_START:
                    ZC_CNT ++;
                    break;
                case AWSS_STATIS_TYPE_TIME_SUC:
                    ZC_SUC ++;
                    break;
                case AWSS_STATIS_TYPE_PASSWD_ERR:
                    ZC_PW_ERR ++;
                    break;
                default:
                    break;
            }
            break;
#endif
        default:
            break;
    }
    HAL_MutexUnlock(awss_statis_mutex);
}

#endif
