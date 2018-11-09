/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#ifndef __AWSS_80211__
#define __AWSS_80211__

#ifdef __cplusplus
extern "C"
{
#endif

int awss_parse_ieee802_11_radio_header(const char *p, int caplen, int8_t *rssi);

#ifdef __cplusplus
}
#endif
#endif
