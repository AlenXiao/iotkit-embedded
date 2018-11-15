/*
 *    Wireless Tools
 *
 *        Jean II - HPLB '99 - HPL 99->07
 *
 * This tool can access various piece of information on the card
 * not part of iwconfig...
 * You need to link this code against "iwlist.c" and "-lm".
 *
 * This file is released under the GPL license.
 * Copyright (c) 1997-2007 Jean Tourrilhes <jt@hpl.hp.com>
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <linux/wireless.h>
#include <linux/if_packet.h>
#include <sys/time.h>

#define AWSS_MAC_STR             "%02X:%02X:%02X:%02X:%02X:%02X"
#define AWSS_MAC2STR(mac)        (((char *)(mac))[0]) & 0xFF, (((char *)(mac))[1]) & 0xFF, (((char *)(mac))[2]) & 0xFF,\
                                 (((char *)(mac))[3]) & 0xFF, (((char *)(mac))[4]) & 0xFF, (((char *)(mac))[5]) & 0xFF
#include "iot_import.h"
#include "awss_scan.h"

/****************************** TYPES ******************************/
#define iwr15_off(f)    (((char *) & (((struct iw15_range *)NULL)->f)) - (char *)NULL)
#define iwr_off(f)      (((char *) &(((struct iw_range *)NULL)->f)) - (char *)NULL)

/*
 *    Struct iw_range up to WE-15
 */
#define IW15_MAX_FREQUENCIES     (16)
#define IW15_MAX_BITRATES        (8)
#define IW15_MAX_TXPOWER         (8)
#define IW15_MAX_ENCODING_SIZES  (8)
struct iw15_range {
    uint32_t throughput;
    uint32_t min_nwid;
    uint32_t max_nwid;
    uint16_t num_channels;
    uint8_t  num_frequency;
    struct iw_freq freq[IW15_MAX_FREQUENCIES];
    int32_t sensitivity;
    struct iw_quality max_qual;
    uint8_t num_bitrates;
    int32_t bitrate[IW15_MAX_BITRATES];
    int32_t min_rts;
    int32_t max_rts;
    int32_t min_frag;
    int32_t max_frag;
    int32_t min_pmp;
    int32_t max_pmp;
    int32_t min_pmt;
    int32_t max_pmt;
    uint16_t pmp_flags;
    uint16_t pmt_flags;
    uint16_t pm_capa;
    uint16_t encoding_size[IW15_MAX_ENCODING_SIZES];
    uint8_t num_encoding_sizes;
    uint8_t max_encoding_tokens;
    uint16_t txpower_capa;
    uint8_t num_txpower;
    int32_t txpower[IW15_MAX_TXPOWER];
    uint8_t we_version_compiled;
    uint8_t we_version_source;
    uint16_t retry_capa;
    uint16_t retry_flags;
    uint16_t r_time_flags;
    int32_t  min_retry;
    int32_t  max_retry;
    int32_t  min_r_time;
    int32_t  max_r_time;
    struct iw_quality avg_qual;
};

/*
 * Union for all the versions of iwrange.
 * Fortunately, I mostly only add fields at the end, and big-bang
 * reorganisations are few.
 */
union iw_range_raw {
    struct iw15_range range15;  /* WE 9->15 */
    struct iw_range range;      /* WE 16->current */
};

int awss_set_ext(
        int skfd,               /* Socket to the kernel */
        const char * ifname,    /* Device name */
        int request,            /* WE ID */
        struct iwreq *pwrq)     /* Fixed part of the request */
{
    /* Set device name */
    strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
    /* Do the request */
    return(ioctl(skfd, request, pwrq));
}

int awss_get_ext(
        int skfd,               /* Socket to the kernel */
        const char * ifname,    /* Device name */
        int request,            /* WE ID */
        struct iwreq *pwrq)     /* Fixed part of the request */
{
    /* Set device name */
    strncpy(pwrq->ifr_name, ifname, IFNAMSIZ);
    /* Do the request */
    return(ioctl(skfd, request, pwrq));
}

/*------------------------------------------------------------------*/
/*
 * Output the link statistics, taking care of formating
 */
void awss_parse_signal_quality(
           const struct iw_quality *qual,
           const struct iw_range *range,
           int has_range, int8_t *rssi)
{
    /* People are very often confused by the 8 bit arithmetic happening
     * here.
     * All the values here are encoded in a 8 bit integer. 8 bit integers
     * are either unsigned [0 ; 255], signed [-128 ; +127] or
     * negative [-255 ; 0].
     * Further, on 8 bits, 0x100 == 256 == 0.
     *
     * Relative/percent values are always encoded unsigned, between 0 and 255.
     * Absolute/dBm values are always encoded between -192 and 63.
     * (Note that up to version 28 of Wireless Tools, dBm used to be
     *  encoded always negative, between -256 and -1).
     *
     * How do we separate relative from absolute values ?
     * The old way is to use the range to do that. As of WE-19, we have
     * an explicit IW_QUAL_DBM flag in updated...
     * The range allow to specify the real min/max of the value. As the
     * range struct only specify one bound of the value, we assume that
     * the other bound is 0 (zero).
     * For relative values, range is [0 ; range->max].
     * For absolute values, range is [range->max ; 63].
     *
     * Let's take two example :
     * 1) value is 75%. qual->value = 75 ; range->max_qual.value = 100
     * 2) value is -54dBm. noise floor of the radio is -104dBm.
     *    qual->value = -54 = 202 ; range->max_qual.value = -104 = 152
     *
     * Jean II
     */

    /* Just do it...
     * The old way to detect dBm require both the range and a non-null
     * level (which confuse the test). The new way can deal with level of 0
     * because it does an explicit test on the flag. */
    if (has_range && ((qual->level != 0) || (qual->updated & (IW_QUAL_DBM | IW_QUAL_RCPI)))) {
        /* Check if the statistics are in RCPI (IEEE 802.11k) */
        /* Check if the statistics are in dBm */
        if ((qual->updated & IW_QUAL_DBM) || (qual->level > range->max_qual.level)) {
            /* Deal with signal level in dBm  (absolute power measurement) */
            if (!(qual->updated & IW_QUAL_LEVEL_INVALID)) {
                int dblevel = qual->level;
                /* Implement a range for dBm [-192; 63] */
                if (qual->level >= 64)
                    dblevel -= 0x100;
                *rssi = dblevel;
            }
        }
    }
}

/***************************** SCANNING *****************************/
/*
 * This one behave quite differently from the others
 *
 * Note that we don't use the scanning capability of iwlib (functions
 * iw_process_scan() and iw_scan()). The main reason is that
 * iw_process_scan() return only a subset of the scan data to the caller,
 * for example custom elements and bitrates are ommited. Here, we
 * do the complete job...
 */

#define AWSS_SCAN_AP_INFO_SSID_BIT  (1 << 0)
#define AWSS_SCAN_AP_INFO_BSSID_BIT (1 << 1)
#define AWSS_SCAN_AP_INFO_CHAN_BIT  (1 << 2)
#define AWSS_SCAN_AP_INFO_RSSI_BIT  (1 << 3)
#define AWSS_SCAN_AP_INFO_MASK      (AWSS_SCAN_AP_INFO_SSID_BIT | AWSS_SCAN_AP_INFO_BSSID_BIT | \
                                     AWSS_SCAN_AP_INFO_CHAN_BIT | AWSS_SCAN_AP_INFO_RSSI_BIT)
#define AWSS_SCAN_AP_INFO_COMPLETE  (AWSS_SCAN_AP_INFO_MASK)
struct awss_scan_ap_info_t {
    char ssid[IW_ESSID_MAX_SIZE + 1];
    int8_t rssi;
    uint16_t channel;
    char bssid[ETH_ALEN];
    uint8_t flag;
};

/*------------------------------------------------------------------*/
/*
 * Print one element from the scanning results
 */
static void awss_parse_event(
        struct iw_event *event,        /* Extracted token */
        struct iw_range *iw_range,     /* Range info */
        int has_range,
        struct awss_scan_ap_info_t *ap_info)
{
    switch (event->cmd) {
        case SIOCGIWAP:
            ap_info->flag |= AWSS_SCAN_AP_INFO_BSSID_BIT; 
            memcpy(ap_info->bssid, &event->u.ap_addr.sa_data, ETH_ALEN);
            break;
        case SIOCGIWFREQ:
            if (event->u.freq.m < 0x1e3)
                ap_info->channel = event->u.freq.m;
            else
                break;
            /* Convert to channel if possible */
            ap_info->flag |= AWSS_SCAN_AP_INFO_CHAN_BIT; 
            break;
      case SIOCGIWESSID:
          memset(ap_info->ssid, 0x00, sizeof(ap_info->ssid));
          ap_info->flag |= AWSS_SCAN_AP_INFO_SSID_BIT; 
          strncpy(ap_info->ssid, event->u.essid.pointer, sizeof(ap_info->ssid)); 
          break;
      case IWEVQUAL:
          awss_parse_signal_quality(&event->u.qual, iw_range, has_range, &ap_info->rssi);
          ap_info->flag |= AWSS_SCAN_AP_INFO_RSSI_BIT; 
          break;
      default:
          break;
      }
}

void awss_init_event_stream(
        struct stream_descr *stream,    /* Stream of events */
        char *data, int len)
{
    /* Cleanup */
    memset((char *) stream, '\0', sizeof(struct stream_descr));

    /* Set things up */
    stream->current = data;
    stream->end = data + len;
}

/*------------------------------------------------------------------*/
/*
 * Get the range information out of the driver
 */
int awss_get_range_info(int skfd, const char *ifname, iwrange *range)
{
    struct iwreq wrq;
    char buffer[sizeof(iwrange) * 2];    /* Large enough */
    union iw_range_raw *range_raw;
    int ret = -1;

    /* Cleanup */
    bzero(buffer, sizeof(buffer));

    wrq.u.data.pointer = (caddr_t) buffer;
    wrq.u.data.length = sizeof(buffer);
    wrq.u.data.flags = 0;

    ret = awss_get_ext(skfd, ifname, SIOCGIWRANGE, &wrq);
    if (ret < 0) {
        printf("SIOCFIWARANGE fail\r\n");
        return(-1);
    }

    /* Point to the buffer */
    range_raw = (union iw_range_raw *) buffer;

    /* For new versions, we can check the version directly, for old versions
     * we use magic. 300 bytes is a also magic number, don't touch... */
    if (wrq.u.data.length < 300) {
        /* That's v10 or earlier. Ouch ! Let's make a guess...*/
        range_raw->range.we_version_compiled = 9;
    }

    /* Check how it needs to be processed */
    if (range_raw->range.we_version_compiled > 15) {
        /* This is our native format, that's easy... */
        /* Copy stuff at the right place, ignore extra */
        memcpy((char *) range, buffer, sizeof(iwrange));
    } else {
        /* Zero unknown fields */
        bzero((char *) range, sizeof(struct iw_range));

        /* Initial part unmoved */
        memcpy((char *) range, buffer, iwr15_off(num_channels));
        /* Frequencies pushed futher down towards the end */
        memcpy((char *) range + iwr_off(num_channels), buffer + iwr15_off(num_channels),
                iwr15_off(sensitivity) - iwr15_off(num_channels));
        /* This one moved up */
        memcpy((char *) range + iwr_off(sensitivity), buffer + iwr15_off(sensitivity),
                iwr15_off(num_bitrates) - iwr15_off(sensitivity));
        /* This one goes after avg_qual */
        memcpy((char *) range + iwr_off(num_bitrates), buffer + iwr15_off(num_bitrates),
                iwr15_off(min_rts) - iwr15_off(num_bitrates));
        /* Number of bitrates has changed, put it after */
        memcpy((char *) range + iwr_off(min_rts), buffer + iwr15_off(min_rts),
                iwr15_off(txpower_capa) - iwr15_off(min_rts));
        /* Added encoding_login_index, put it after */
        memcpy((char *) range + iwr_off(txpower_capa), buffer + iwr15_off(txpower_capa),
                iwr15_off(txpower) - iwr15_off(txpower_capa));
        /* Hum... That's an unexpected glitch. Bummer. */
        memcpy((char *) range + iwr_off(txpower), buffer + iwr15_off(txpower),
                iwr15_off(avg_qual) - iwr15_off(txpower));
        /* Avg qual moved up next to max_qual */
        memcpy((char *) range + iwr_off(avg_qual), buffer + iwr15_off(avg_qual), sizeof(struct iw_quality));
    }

    return(0);
}

/*------------------------------------------------------------------*/
/*
 * Extract the next event from the event stream.
 */
int awss_extract_event_stream(
        struct stream_descr *stream,  /* Stream of events */
        struct iw_event *iwe)         /* Extracted event */

{
    char *pointer;
    unsigned int event_len = 0;
    /* Check for end of stream */
    if ((stream->current + IW_EV_LCP_PK_LEN) > stream->end)
        return (0);

    /* Extract the event header (to get the event id).
     * Note : the event may be unaligned, therefore copy... */
    memcpy((char *) iwe, stream->current, IW_EV_LCP_PK_LEN);

    /* Check invalid events */
    if (iwe->len <= IW_EV_LCP_PK_LEN)
        return (-1);

    /* Set pointer on data */
    if (stream->value != NULL)
        pointer = stream->value;            /* Next value in event */
    else
        pointer = stream->current + IW_EV_LCP_PK_LEN;    /* First value in event */

    stream->current += iwe->len;
#if 0 
    int i;
    for (i = 0; i < iwe->len; i ++)
        printf("%02X:", stream->current[i] & 0xFF);
    printf("\n\n");
#endif
    switch (iwe->cmd) {
        case SIOCGIWAP:
            event_len = IW_EV_ADDR_PK_LEN; 
            event_len -= IW_EV_LCP_PK_LEN;
            pointer += 4;
            memcpy((char *) iwe + IW_EV_LCP_LEN, pointer, event_len);
            break;
        case SIOCGIWFREQ:
            event_len = IW_EV_FREQ_PK_LEN; 
            event_len -= IW_EV_LCP_PK_LEN;
            pointer += 4;
            memcpy((char *) iwe + IW_EV_LCP_LEN, pointer, event_len);
            break;
        case IWEVQUAL:
            /* Beware of alignement. Dest has local alignement, not packed */
            event_len = IW_EV_QUAL_PK_LEN;    /* IW_HEADER_TYPE_QUAL */
            event_len -= IW_EV_LCP_PK_LEN;
            pointer += 4;
            memcpy((char *) iwe + IW_EV_LCP_LEN, pointer, event_len);
            break;
        case SIOCGIWESSID:
            event_len = IW_EV_POINT_PK_LEN; /* Without variable payload */
            event_len -= IW_EV_LCP_PK_LEN;
            pointer += 4;
            memcpy((char *) iwe + IW_EV_LCP_LEN + IW_EV_POINT_OFF, pointer, event_len);
            pointer += event_len + 4;
            iwe->u.data.pointer = pointer;
            break;
        default:
            return (1);
    }
    return 2;
}

/*------------------------------------------------------------------*/
/*
 * Perform a scanning on one device
 */
static int awss_process_scan(int skfd, char *ifname, awss_wifi_scan_result_cb_t cb)
{
    struct iwreq wrq;
    int scanflags = 0;              /* Flags for scan */
    struct iw_scan_req scanopt;     /* Options for 'set' */
    unsigned char *buffer = NULL;   /* Results */
    int buflen = IW_SCAN_MAX_DATA;  /* Min for compat WE<17 */
    struct iw_range range;
    int has_range;
    struct timeval tv;              /* Select timeout */
    int timeout = 15000000;         /* 15s */

    /* Get range stuff */
    has_range = (awss_get_range_info(skfd, ifname, &range) >= 0);
    printf("has_range:%d, version:%d\r\n", has_range, range.we_version_compiled);

    /* Check if the interface could support scanning. */
    if ((!has_range) || (range.we_version_compiled < 14)) {
        fprintf(stderr, "%-8.16s  Interface doesn't support scanning.\n\n", ifname);
        return(-1);
    }

    /* Init timeout value -> 250ms between set and first get */
    tv.tv_sec = 0;
    tv.tv_usec = 250000;

    /* Clean up set args */
    memset(&scanopt, 0, sizeof(scanopt));

    /* Check if we have scan options */
    if (scanflags == 0) {
        int ch = 0, idx = 0;
        scanflags |= IW_SCAN_ALL_FREQ;
        scanopt.scan_type = IW_SCAN_TYPE_PASSIVE;
        //scanopt.scan_type = IW_SCAN_TYPE_ACTIVE;
        scanopt.num_channels = range.num_channels;
        for (ch = 0; ch < range.num_channels; ch ++) {
            if (range.freq[ch].i <= 14)
                memcpy(&scanopt.channel_list[idx ++], &range.freq[ch], sizeof(range.freq[0]));
        }
        scanopt.num_channels = idx;
        memcpy(scanopt.channel_list, range.freq, sizeof(range.freq[0]) * range.num_channels);
    }
    wrq.u.data.pointer = (caddr_t) &scanopt;
    wrq.u.data.length = sizeof(scanopt);
    wrq.u.data.flags = scanflags;

    /* Initiate Scanning */
    if (awss_set_ext(skfd, ifname, SIOCSIWSCAN, &wrq) < 0) {
        if ((errno != EPERM) || (scanflags != 0)) {
            fprintf(stderr, "%-8.16s  Interface doesn't support scanning : %s\n\n", ifname, strerror(errno));
            return(-1);
        }
        tv.tv_usec = 0;
    }
    timeout -= tv.tv_usec;

    /* Forever */
    while (1) {
        fd_set rfds;    /* File descriptors for select */
        int last_fd;    /* Last fd */
        int ret;

        /* Guess what ? We must re-generate rfds each time */
        FD_ZERO(&rfds);
        FD_SET(skfd, &rfds);
        last_fd = skfd;

        /* In here, add the rtnetlink fd in the list */

        printf("last_fd:%d\n", last_fd);
        /* Wait until something happens */
        ret = select(last_fd + 1, &rfds, NULL, NULL, &tv);

        /* Check if there was an error */
        if (ret < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            fprintf(stderr, "Unhandled signal - exiting...\n");
            return(-1);
        }
        printf("ret:%d\n", ret);

        /* Check if there was a timeout */
        if (ret == 0) {
            unsigned char *newbuf;
realloc:
            printf("buflen:%u\n", buflen);
            /* (Re)allocate the buffer - realloc(NULL, len) == malloc(len) */
            newbuf = realloc(buffer, buflen);
            if (newbuf == NULL) {
                if (buffer)
                    free(buffer);
                fprintf(stderr, "%s: Allocation %u failed\n", __FUNCTION__, buflen);
                return(-1);
            }
            buffer = newbuf;

            /* Try to read the results */
            wrq.u.data.pointer = buffer;
            wrq.u.data.flags = 0;
            wrq.u.data.length = buflen;
            if (awss_get_ext(skfd, ifname, SIOCGIWSCAN, &wrq) < 0) {
                /* Check if buffer was too small (WE-17 only) */
                if ((errno == E2BIG) && (range.we_version_compiled > 16)) {
                    /* Some driver may return very large scan results, either
                     * because there are many cells, or because they have many
                     * large elements in cells (like IWEVCUSTOM). Most will
                     * only need the regular sized buffer. We now use a dynamic
                     * allocation of the buffer to satisfy everybody. Of course,
                     * as we don't know in advance the size of the array, we try
                     * various increasing sizes. Jean II 
                     */

                    printf("%s, %u\n", __func__, __LINE__);
                    printf("error:%d, compiled:%d\n", errno, range.we_version_compiled);
                    /* Check if the driver gave us any hints. */
                    if (wrq.u.data.length > buflen)
                        buflen = wrq.u.data.length;
                    else
                        buflen *= 2;

                    /* Try again */
                    goto realloc;
                }

                /* Check if results not available yet */
                if (errno == EAGAIN) {
                    /* Restart timer for only 100ms*/
                    tv.tv_sec = 0;
                    tv.tv_usec = 100000;
                    timeout -= tv.tv_usec;
                    printf("%s, %u\n", __func__, __LINE__);
                    if (timeout > 0)
                        continue;    /* Try again later */
                }

                /* Bad error */
                free(buffer);
                fprintf(stderr, "%-8.16s  Failed to read scan data : %s\n\n", ifname, strerror(errno));

                return(-2);
            } else {
                /* We have the results, go to process them */
                break;
            }
        }

        /* In here, check if event and event type
         * if scan event, read results. All errors bad & no reset timeout
         */
    }

    if (wrq.u.data.length) {
        int ret;
        struct iw_event iwe;
        struct stream_descr stream;
        struct awss_scan_ap_info_t scan_ap;

        printf("%-8.16s  Scan completed :\n", ifname);
        memset(&scan_ap, 0, sizeof(scan_ap));
        awss_init_event_stream(&stream, (char *)buffer, wrq.u.data.length);

        /* Extract an event and print it */
        ret = awss_extract_event_stream(&stream, &iwe);
        while (ret > 0) {
            if (ret > 1)
                awss_parse_event(&iwe, &range, has_range, &scan_ap);
            ret = awss_extract_event_stream(&stream, &iwe);
            if (ret > 1 && (scan_ap.flag & AWSS_SCAN_AP_INFO_MASK) == AWSS_SCAN_AP_INFO_COMPLETE) {
                cb((const char *)scan_ap.ssid, (const uint8_t *)scan_ap.bssid, 0, 0, (uint8_t)scan_ap.channel, scan_ap.rssi, 0);
                memset(&scan_ap, 0, sizeof(scan_ap));
            }
        };
        if ((scan_ap.flag & AWSS_SCAN_AP_INFO_MASK) == AWSS_SCAN_AP_INFO_COMPLETE)
            cb((const char *)scan_ap.ssid, (const uint8_t *)scan_ap.bssid, 0, 0, (uint8_t)scan_ap.channel, scan_ap.rssi, 1);
    } else {
        printf("%-8.16s  No scan results\n\n", ifname);
    }

    free(buffer);
    return(0);
}

int awss_scan(char *dev, awss_wifi_scan_result_cb_t cb)
{
    int skfd = -1;
    /* Create a channel to the NET kernel. */
    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket");
        return -1;
    }

    awss_process_scan(skfd, dev, cb);

    /* Close the socket. */
    close(skfd);

    return 0;
}
