/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include "iot_import.h"
#include "iot_export.h"

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
extern "C"
{
#endif

int awss_event_post(int event)
{
    return iotx_event_post(event);
}

#if defined(__cplusplus)  /* If this is a C++ compiler, use C linkage */
}
#endif
