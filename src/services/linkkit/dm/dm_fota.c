/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */



#include "iotx_dm_internal.h"

#ifdef OTA_ENABLED
static dm_fota_ctx_t g_dm_fota_ctx;

static dm_fota_ctx_t *_dm_fota_get_ctx(void)
{
    return &g_dm_fota_ctx;
}
#endif

int dm_fota_init(void)
{
#ifdef OTA_ENABLED
    dm_fota_ctx_t *ctx = _dm_fota_get_ctx();

    memset(ctx, 0, sizeof(dm_fota_ctx_t));
#endif
    return SUCCESS_RETURN;
}

int dm_fota_deinit(void)
{
#ifdef OTA_ENABLED
    dm_fota_ctx_t *ctx = _dm_fota_get_ctx();

    memset(ctx, 0, sizeof(dm_fota_ctx_t));
#endif
    return SUCCESS_RETURN;
}

#ifdef OTA_ENABLED
static int _dm_fota_send_new_config_to_user(void *ota_handle)
{
    int res = 0, message_len = 0;
    char *message = NULL;
    char version[128] = {0};
    const char *fota_new_config_fmt = "{\"version\":\"%s\"}";

    IOT_OTA_Ioctl(ota_handle, IOT_OTAG_VERSION, version, 128);

    message_len = strlen(fota_new_config_fmt) + strlen(version) + 1;

    message = DM_malloc(message_len);
    if (message == NULL) {
        return DM_MEMORY_NOT_ENOUGH;
    }
    memset(message, 0, message_len);
    HAL_Snprintf(message, message_len, fota_new_config_fmt, version);

    dm_log_info("Send To User: %s", message);

    res = _dm_msg_send_to_user(IOTX_DM_EVENT_FOTA_NEW_FIRMWARE, message);
    if (res != SUCCESS_RETURN) {
        if (message) {
            DM_free(message);
        }
        return FAIL_RETURN;
    }

    return SUCCESS_RETURN;
}
#endif

int dm_fota_perform_sync(_OU_ char *output, _IN_ int output_len)
{
#ifdef OTA_ENABLED
    int res = 0, file_download = 0;
    uint32_t file_size = 0, file_downloaded = 0;
    uint32_t percent_pre = 0, percent_now = 0;
    unsigned long long report_pre = 0, report_now = 0;
    dm_fota_ctx_t *ctx = _dm_fota_get_ctx();
    void *ota_handle = NULL;
    uint32_t ota_type = IOT_OTAT_NONE;

    if (output == NULL || output_len <= 0) {
        return DM_INVALID_PARAMETER;
    }

    /* Get Ota Handle */
    res = dm_ota_get_ota_handle(&ota_handle);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    if (ota_handle == NULL) {
        return FAIL_RETURN;
    }
    IOT_OTA_Ioctl(ota_handle, IOT_OTAG_OTA_TYPE, &ota_type, 4);

    if (ota_type != IOT_OTAT_FOTA) {
        return FAIL_RETURN;
    }

    /* reset the size_fetched in ota_handle to be 0 */
    IOT_OTA_Ioctl(ota_handle, IOT_OTAG_RESET_FETCHED_SIZE, ota_handle, 4);
    /* Prepare Write Data To Storage */
    HAL_Firmware_Persistence_Start();
    ctx->is_report_new_config = 0;
    while (1) {
        file_download = IOT_OTA_FetchYield(ota_handle, output, output_len, 1);
        if (file_download < 0) {
            IOT_OTA_ReportProgress(ota_handle, IOT_OTAP_FETCH_FAILED, NULL);
            HAL_Firmware_Persistence_Stop();
            return FAIL_RETURN;
        }

        /* Write Config File Into Stroage */
        HAL_Firmware_Persistence_Write(output, file_download);

        /* Get OTA information */
        IOT_OTA_Ioctl(ota_handle, IOT_OTAG_FETCHED_SIZE, &file_downloaded, 4);
        IOT_OTA_Ioctl(ota_handle, IOT_OTAG_FILE_SIZE, &file_size, 4);

        /* Calculate Download Percent And Update Report Timestamp*/
        percent_now = (file_downloaded * 100) / file_size;
        report_now = HAL_UptimeMs();

        /* Report Download Process To Cloud */
        if (report_now < report_pre) {
            report_pre = report_now;
        }
        if ((((percent_now - percent_pre) > 5) &&
             ((report_now - report_pre) > 50)) || (percent_now >= IOT_OTAP_FETCH_PERCENTAGE_MAX)) {
            IOT_OTA_ReportProgress(ota_handle, percent_now, NULL);
            percent_pre = percent_now;
            report_pre = report_now;
        }

        /* Check If OTA Finished */
        if (IOT_OTA_IsFetchFinish(ota_handle)) {
            uint32_t file_isvalid = 0;
            IOT_OTA_Ioctl(ota_handle, IOT_OTAG_CHECK_FIRMWARE, &file_isvalid, 4);
            if (file_isvalid == 0) {
                HAL_Firmware_Persistence_Stop();
                return FAIL_RETURN;
            } else {
                break;
            }
        }
    }

    HAL_Firmware_Persistence_Stop();
#endif
    return SUCCESS_RETURN;
}

int dm_fota_status_check(void)
{
#ifdef OTA_ENABLED
    int res = 0;
    dm_fota_ctx_t *ctx = _dm_fota_get_ctx();
    void *ota_handle = NULL;

    /* Get Ota Handle */
    res = dm_ota_get_ota_handle(&ota_handle);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    if (IOT_OTA_IsFetching(ota_handle)) {
        uint32_t ota_type = IOT_OTAT_NONE;

        IOT_OTA_Ioctl(ota_handle, IOT_OTAG_OTA_TYPE, &ota_type, 4);

        if (ota_type == IOT_OTAT_FOTA) {
            /* Send New Config Information To User */
            if (ctx->is_report_new_config == 0) {
                dm_log_debug("Fota Status Check");
                res = _dm_fota_send_new_config_to_user(ota_handle);
                if (res == SUCCESS_RETURN) {
                    ctx->is_report_new_config = 1;
                }
            }
        }
    }
#endif
    return SUCCESS_RETURN;
}

int dm_fota_request_image(const char *version, int buffer_len)
{
#ifdef OTA_ENABLED
    int res = 0;
    void *ota_handle = NULL;

    if (NULL == version || buffer_len <= 0) {
        dm_log_info("invalid input");
        return FAIL_RETURN;
    }

    /* Get Ota Handle */
    res = dm_ota_get_ota_handle(&ota_handle);
    if (res != SUCCESS_RETURN) {
        return FAIL_RETURN;
    }

    char *version_str = DM_malloc(buffer_len + 1);
    if (NULL == version_str) {
        dm_log_info("failed to malloc");
        return FAIL_RETURN;
    }
    memset(version_str, 0, buffer_len + 1);
    memcpy(version_str, version, buffer_len);

    int ret = IOT_OTA_RequestImage(ota_handle, version_str);
    DM_free(version_str);
    return ret;
#else
    return SUCCESS_RETURN;
#endif
}
