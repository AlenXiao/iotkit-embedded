/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include "awss.h"
#include "awss_main.h"
#include "zconfig_utils.h"
#include "awss_enrollee.h"
#include "awss_packet.h"
#include "awss_timer.h"
#include "awss_statis.h"
#include "awss_event.h"
#include "passwd.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C" {
#endif

#define AWSS_PRESS_TIMEOUT_MS  (60000)

static uint8_t awss_stopped = 1;
static uint8_t g_user_press = 0;
static void *press_timer = NULL;

static void awss_press_timeout(void);

int awss_start(void)
{
    if (awss_stopped == 0) {
        awss_warn("awss exist\n");
        return -1;
    }

    awss_stopped = 0;
    awss_event_post(AWSS_START);
    produce_random(aes_random, sizeof(aes_random));

    do {
        __awss_start();
        if (awss_stopped) {
            break;
        }

        if (os_sys_net_is_ready()) {
            break;
        }
    } while (1);

    if (awss_stopped)
        return -1;

    awss_stopped = 1;

    return 0;
}

int awss_stop(void)
{
    awss_stopped = 1;
    g_user_press = 0;
    awss_press_timeout();

    __awss_stop();

    return 0;
}

static void awss_press_timeout(void)
{
    awss_stop_timer(press_timer);
    press_timer = NULL;
    if (g_user_press) {
        awss_event_post(AWSS_ENABLE_TIMEOUT);
    }
    g_user_press = 0;
}

int awss_config_press(void)
{
    int timeout = os_awss_get_timeout_interval_ms();

    awss_trace("enable awss\r\n");

    g_user_press = 1;

    awss_event_post(AWSS_ENABLE);

    if (press_timer == NULL) {
        press_timer = HAL_Timer_Create("press", (void (*)(void *))awss_press_timeout, NULL);
    }
    if (press_timer == NULL) {
        return -1;
    }

    HAL_Timer_Stop(press_timer);

    if (timeout < AWSS_PRESS_TIMEOUT_MS) {
        timeout = AWSS_PRESS_TIMEOUT_MS;
    }
    HAL_Timer_Start(press_timer, timeout);

    return 0;
}

uint8_t awss_get_config_press(void)
{
    return g_user_press;
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif
