/*
 * Copyright (C) 2015-2018 Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <linux/wireless.h>
#include <linux/if_packet.h>

#include "iot_import.h"
#include "awss_80211.h"

#define AWSS_IS_INVALID_MAC(mac) (((char *)(mac))[0] == 0 && ((char *)(mac))[1] == 0 && ((char *)(mac))[2] == 0 && \
                                  ((char *)(mac))[3] == 0 && ((char *)(mac))[4] == 0 && ((char *)(mac))[5] == 0)
#define AWSS_MAC_STR             "%02X:%02X:%02X:%02X:%02X:%02X"
#define AWSS_MAC2STR(mac)        (((char *)(mac))[0]) & 0xFF, (((char *)(mac))[1]) & 0xFF, (((char *)(mac))[2]) & 0xFF,\
                                 (((char *)(mac))[3]) & 0xFF, (((char *)(mac))[4]) & 0xFF, (((char *)(mac))[5]) & 0xFF
#define AWSS_PROC_NET_DEV        "/proc/net/dev"
#define AWSS_MONITOR_DEV_NAME    "awss_mon"
#define AWSS_AP_RECORD_KEY       "awss_ap_record"

struct awss_ap_record_t {
    uint8_t bssid[ETH_ALEN];
    char ssid[HAL_MAX_SSID_LEN];
    char passwd[HAL_MAX_PASSWD_LEN];
};

static char awss_dev_name[IFNAMSIZ + 1];
static pthread_t awss_monitor_thread;
static char awss_monitor_running;
static char awss_dev_mac[ETH_ALEN];

static void awss_system(const char *buf)
{
    if (buf == NULL)
        return;
    if (system(buf))
        printf("cmd %s fail\n", buf);
}

/*
 * Extract the interface name out of /proc/net/dev.
 */
static char * awss_get_ifname(
        char *name,    /* Where to store the name */
        int  nsize,    /* Size of name buffer */
        char *buf)     /* Current position in buffer */
{
    char *end;

    /* Skip leading spaces */
    while (isspace(*buf)) buf ++;

    /* Get name up to the last ':'. Aliases may contain ':' in them,
     * but the last one should be the separator */
    end = strrchr(buf, ':');

    /* Not found ??? To big ??? */
    if (end == NULL || (end - buf) + 1 > nsize)
        return NULL;

    /* Return value currently unused, just make sure it's non-NULL */
    memcpy(name, buf, (end - buf));
    name[end - buf] = '\0';

    return end;
}

static int awss_get_dev_mac()
{
    struct ifreq ifr;
    int skfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (skfd <= 0) {
        perror("socket error!\n");
        return -1;
    }

    strcpy(ifr.ifr_name, awss_dev_name);

    if (ioctl(skfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR error\n");
        close(skfd);
        return -1;
    } else {
        memcpy(awss_dev_mac, ifr.ifr_hwaddr.sa_data, sizeof(awss_dev_mac));
    }

    close(skfd);

    return 0;
}

int awss_get_dev_name()
{
    char buff[256];
    FILE *fh;
    int skfd;

    fh = fopen(AWSS_PROC_NET_DEV, "r");
    if (fh == NULL) {
        perror("get dev name open " AWSS_PROC_NET_DEV " fail\n");
        return -1;
    }

    /* Try to open the socket, if success returns it */
    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    if (skfd <= 0) {
        perror("get dev name open socket fail\n");
        return -1;
    }

    /* Read each device line */
    while (fgets(buff, sizeof(buff), fh)) {
        char name[IFNAMSIZ + 1];
        char *s;

        /* Skip empty or almost empty lines. It seems that in some
         * cases fgets return a line with only a newline. */
        if ((buff[0] == '\0') || (buff[1] == '\0'))
            continue;

        /* Extract interface name */
        s = awss_get_ifname(name, sizeof(name), buff);
        if (s) {
            struct iwreq wrq;
            strncpy(wrq.ifr_name, name, IFNAMSIZ);
             /* if fail to get iw name about this interface
              * the interface maybe not wireless interface
              * skip the interface which is not wireless */
            if (ioctl(skfd, SIOCGIWNAME, &wrq) < 0)
                continue;
            strncpy(awss_dev_name, name, sizeof(awss_dev_name));
            awss_get_dev_mac();
            break;
        }
    }
#if 0
    fprintf(stderr, "name: %s ", awss_dev_name);
    fprintf(stderr, "%02x:%02x:%02x:%02x:%02x:%02x\n",
            (unsigned char)awss_dev_mac[0], (unsigned char)awss_dev_mac[1],
            (unsigned char)awss_dev_mac[2], (unsigned char)awss_dev_mac[3],
            (unsigned char)awss_dev_mac[4], (unsigned char)awss_dev_mac[5]);
#endif
    close(skfd);
    fclose(fh);

    return AWSS_IS_INVALID_MAC(awss_dev_mac) ? -1 : 0;
}

/**
 * @brief   获取`smartconfig`服务的安全等级
 *
 * @param None.
 * @return The security level:
   @verbatim
    0: open (no encrypt)
    1: aes256cfb with default aes-key and aes-iv
    2: aes128cfb with default aes-key and aes-iv
    3: aes128cfb with aes-key per product and aes-iv = 0
    4: aes128cfb with aes-key per device and aes-iv = 0
    5: aes128cfb with aes-key per manufacture and aes-iv = 0
    others: invalid
   @endverbatim
 * @see None.
 */
int HAL_Awss_Get_Encrypt_Type()
{
    return 3;
}

/**
 * @brief    Get Security level for wifi configuration with connection.
 *           Used for AP solution of router and App.
 *
 * @param None.
 * @return The security level:
   @verbatim
    3: aes128cfb with aes-key per product and aes-iv = random
    4: aes128cfb with aes-key per device and aes-iv = random
    5: aes128cfb with aes-key per manufacture and aes-iv = random
    others: invalid
   @endverbatim
 * @see None.
 */
int HAL_Awss_Get_Conn_Encrypt_Type()
{
    return 4;
}

/**
 * @brief   获取Wi-Fi网口的MAC地址, 格式应当是"XX:XX:XX:XX:XX:XX"
 *
 * @param   mac_str : 用于存放MAC地址字符串的缓冲区数组
 * @return  指向缓冲区数组起始位置的字符指针
 */
char *HAL_Wifi_Get_Mac(_OU_ char mac_str[HAL_MAC_LEN])
{
    if (AWSS_IS_INVALID_MAC(awss_dev_mac))
        return NULL;
    snprintf(mac_str, HAL_MAC_LEN, AWSS_MAC_STR, AWSS_MAC2STR(awss_dev_mac));
    return mac_str;
}

/**
 * @brief   获取配网服务(`AWSS`)的超时时间长度, 单位是毫秒
 *
 * @return  超时时长, 单位是毫秒
 * @note    推荐时长是60,0000毫秒
 */
int HAL_Awss_Get_Timeout_Interval_Ms(void)
{
    return 30 * 60 * 1000;
}

/**
 * @brief   获取在每个信道(`channel`)上扫描的时间长度, 单位是毫秒
 *
 * @return  时间长度, 单位是毫秒
 * @note    推荐时长是200毫秒到400毫秒
 */
int HAL_Awss_Get_Channelscan_Interval_Ms(void)
{
    return 250;
}

int awss_open_monitor_socket(void)
{
    struct sockaddr_ll ll;
    struct ifreq ifr;
    int sockopt = 1;
    int fd;

    if (getuid() != 0)
        perror("root privilege needed!\n");

    //create a raw socket that shall sniff
    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    assert(fd >= 0);

    memset(&ifr, 0, sizeof(ifr));

    if (awss_dev_name[0] == '\0') {
        perror("dev name is invalid");
        goto exit;
    }
    /* set interface to promiscuous mode */
    strncpy(ifr.ifr_name, AWSS_MONITOR_DEV_NAME, sizeof(ifr.ifr_name));
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCGIFFLAGS) fail");
        goto exit;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS) fail");
        goto exit;
    }

    /* allow the socket to be reused */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   &sockopt, sizeof(sockopt)) < 0) {
        perror("setsockopt(SO_REUSEADDR) fail");
        goto exit;
    }

    /* bind to device */
    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = if_nametoindex(awss_dev_name);
    if (bind(fd, (struct sockaddr *)&ll, sizeof(ll)) < 0) {
        perror("bind[PF_PACKET] failed");
        goto exit;
    }

    return fd;
exit:
    close(fd);
    exit(EXIT_FAILURE);
}

void *awss_monitor_thread_func(void *arg)
{
    awss_recv_80211_frame_cb_t ieee80211_handler = (awss_recv_80211_frame_cb_t)arg;
    /* buffer to hold the 80211 frame */
    char *ether_frame = malloc(IP_MAXPACKET);
    assert(ether_frame);

    int fd = awss_open_monitor_socket();
    int len, ret;
    fd_set rfds;
    struct timeval tv;

    while (awss_monitor_running) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);

        tv.tv_sec = 0;
        tv.tv_usec = 100 * 1000;//100ms

        ret = select(fd + 1, &rfds, NULL, NULL, &tv);
        assert(ret >= 0);

        if (!ret)
            continue;

        //memset(ether_frame, 0, IP_MAXPACKET);
        len = recv(fd, ether_frame, IP_MAXPACKET, 0);
        if (len < 0) {
            perror ("recv() failed:");
            //Something weird happened
            continue;
        }

        /*
         * Note: use tcpdump -i wlan0 -w file.pacp to check link type and FCS
         */

        int with_fcs = 1;
        int8_t rssi = -1;
        /* link-type IEEE802_11_RADIO (802.11 plus radiotap header) */
        int link_type = AWSS_LINK_TYPE_80211_RADIO;

        awss_parse_ieee802_11_radio_header(ether_frame, len, &rssi);

        (*ieee80211_handler)(ether_frame, len, link_type, with_fcs, rssi);
    }

    free(ether_frame);
    close(fd);

    return NULL;
}

/**
 * @brief   设置Wi-Fi网卡工作在监听(Monitor)模式, 并在收到802.11帧的时候调用被传入的回调函数
 *
 * @param[in] cb @n A function pointer, called back when wifi receive a frame.
 */
void HAL_Awss_Open_Monitor(_IN_ awss_recv_80211_frame_cb_t cb)
{
    char buf[256];
    int ret = 0;

    ret = awss_get_dev_name();
    if (strcmp(awss_dev_name, AWSS_MONITOR_DEV_NAME) == 0) {  // the last time is ended with exception
        // clear context of the last time
        snprintf(buf, sizeof(buf), "sudo iw dev %s del", awss_dev_name);
        awss_system(buf);
        ret = -1;
    }

    if (ret) {  // set default wlan0 for new operation
        strncpy(awss_dev_name, "wlan0", sizeof(awss_dev_name));
        snprintf(buf, sizeof(buf), "sudo iw phy phy0 interface add %s type managed", awss_dev_name);
        awss_system(buf);
        snprintf(buf, sizeof(buf), "sudo ifconfig %s up", awss_dev_name);
        awss_system(buf);
        awss_get_dev_name();
    }

    snprintf(buf, sizeof(buf), "sudo iw phy phy0 interface add %s type monitor", AWSS_MONITOR_DEV_NAME);
    awss_system(buf);

    snprintf(buf, sizeof(buf), "sudo ifconfig %s down", awss_dev_name);
    awss_system(buf);

    snprintf(buf, sizeof(buf), "sudo iw dev %s del", awss_dev_name);
    awss_system(buf);

    snprintf(buf, sizeof(buf), "sudo ifconfig %s up", AWSS_MONITOR_DEV_NAME);
    awss_system(buf);

    awss_monitor_running = 1;

    ret = pthread_create(&awss_monitor_thread, NULL, awss_monitor_thread_func, cb);
    assert(!ret);
}

/**
 * @brief   设置Wi-Fi网卡离开监听(Monitor)模式, 并开始以站点(Station)模式工作
 */
void HAL_Awss_Close_Monitor(void)
{
    char buf[256];

    awss_monitor_running = 0;

    pthread_join(awss_monitor_thread, NULL);

    snprintf(buf, sizeof(buf), "sudo iw phy phy0 interface add %s type managed", awss_dev_name);
    awss_system(buf);

    snprintf(buf, sizeof(buf), "sudo ifconfig %s down", AWSS_MONITOR_DEV_NAME);
    awss_system(buf);

    snprintf(buf, sizeof(buf), "sudo iw dev %s del", AWSS_MONITOR_DEV_NAME);
    awss_system(buf);

    snprintf(buf, sizeof(buf), "sudo ifconfig %s up", awss_dev_name);
    awss_system(buf);
}

/**
 * @brief   设置Wi-Fi网卡切换到指定的信道(channel)上
 *
 * @param[in] primary_channel @n Primary channel.
 * @param[in] secondary_channel @n Auxiliary channel if 40Mhz channel is supported, currently
 *              this param is always 0.
 * @param[in] bssid @n A pointer to wifi BSSID on which awss lock the channel, most HAL
 *              may ignore it.
 */
void HAL_Awss_Switch_Channel(
            _IN_ char primary_channel,
            _IN_OPT_ char secondary_channel,
            _IN_OPT_ uint8_t bssid[ETH_ALEN])
{
    char buf[256];
    snprintf(buf, sizeof(buf), "sudo iwconfig %s channel %d", AWSS_MONITOR_DEV_NAME, primary_channel);
    awss_system(buf);
}

int awss_connect_last_ap()
{
    int ret = -1;
    struct awss_ap_record_t last_ap;
    int len = sizeof(struct awss_ap_record_t);

    do {
        uint8_t bcast_bssid[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

        memset(&last_ap, 0, sizeof(last_ap));

        if (HAL_Kv_Get(AWSS_AP_RECORD_KEY, &last_ap, &len) != 0)
            break;

        if (awss_get_dev_name() != 0)
            break;

        if (memcmp(last_ap.bssid, bcast_bssid, ETH_ALEN) == 0)  // invalid bssid
            memset(last_ap.bssid, 0, ETH_ALEN);

        if (HAL_Awss_Connect_Ap(30000, last_ap.ssid, last_ap.passwd, 0, 0, last_ap.bssid, 0) != 0)
            break;

        ret = 0;
    } while (0);

    return ret;
}

/**
 * @brief   要求Wi-Fi网卡连接指定热点(Access Point)的函数
 *
 * @param[in] connection_timeout_ms @n AP connection timeout in ms or HAL_WAIT_INFINITE
 * @param[in] ssid @n AP ssid
 * @param[in] passwd @n AP passwd
 * @param[in] auth @n optional(AWSS_AUTH_TYPE_INVALID), AP auth info
 * @param[in] encry @n optional(AWSS_ENC_TYPE_INVALID), AP encry info
 * @param[in] bssid @n optional(NULL or zero mac address), AP bssid info
 * @param[in] channel @n optional, AP channel info
 * @return
   @verbatim
     = 0: connect AP & DHCP success
     = -1: connect AP or DHCP fail/timeout
   @endverbatim
 * @see None.
 * @note
 *      If the STA connects the old AP, HAL should disconnect from the old AP firstly.
 *      If bssid specifies the dest AP, HAL should use bssid to connect dest AP.
 */
int HAL_Awss_Connect_Ap(
            _IN_ uint32_t connection_timeout_ms,
            _IN_ char ssid[HAL_MAX_SSID_LEN],
            _IN_ char passwd[HAL_MAX_PASSWD_LEN],
            _IN_OPT_ enum AWSS_AUTH_TYPE auth,
            _IN_OPT_ enum AWSS_ENC_TYPE encry,
            _IN_OPT_ uint8_t bssid[ETH_ALEN],
            _IN_OPT_ uint8_t channel)
{
    int ret = -1;
    char buf[256];
    uint64_t cur, time = HAL_UptimeMs();

    snprintf(buf, sizeof(buf), "sudo ifconfig %s up", awss_dev_name);
    awss_system(buf);

    if (HAL_Sys_Net_Is_Ready()) {
        uint8_t cur_bssid[ETH_ALEN] = {0};
        char cur_ssid[HAL_MAX_SSID_LEN] = {0};

        HAL_Wifi_Get_Ap_Info(cur_ssid, NULL, cur_bssid);
        if (strcmp(ssid, cur_ssid) == 0 &&
            (!bssid || memcmp(bssid, cur_bssid, ETH_ALEN) == 0))
            return 0;

        snprintf(buf, sizeof(buf), "sudo nmcli dev dis %s", awss_dev_name);
        awss_system(buf);
        usleep(100 * 1000);
    }

    if (bssid && !AWSS_IS_INVALID_MAC(bssid)) {
        snprintf(buf, sizeof(buf), "sudo nmcli device wifi connect %s password %s bssid " AWSS_MAC_STR, ssid, passwd, AWSS_MAC2STR(bssid));
    } else {  // no specific bssid
        snprintf(buf, sizeof(buf), "sudo nmcli device wifi connect %s password %s", ssid, passwd);
    }

    cur = HAL_UptimeMs();
    if (cur - time > connection_timeout_ms)
        return -1;

    //TODO: wait dhcp ready here
    while (HAL_Sys_Net_Is_Ready() == 0) {
        cur = HAL_UptimeMs();
        if (cur - time > connection_timeout_ms)
            break;
        awss_system(buf);
        usleep(1000 * 1000);
    }

    ret = HAL_Sys_Net_Is_Ready() ? 0 : -1;

    do {
        int len;
        const char *aha = "aha";
        const char *adha = "adha";
        struct awss_ap_record_t ap_record;
        if (ret != 0)
            break;
        // HAL_MAX_SSID_LEN = 32 + 1
        // HAL_MX_PASSWD_LEN = 64 + 1
        ssid[HAL_MAX_SSID_LEN - 1] = '\0';
        passwd[HAL_MAX_PASSWD_LEN - 1] = '\0';

        // filter aha & adha
        if (strlen(ssid) == strlen(aha) && strcmp(ssid, aha) == 0)
            break;
        if (strlen(ssid) != strlen(adha) && strcmp(ssid, adha) == 0)
            break;

        memset(&ap_record, 0, sizeof(ap_record));
        strncpy(ap_record.ssid, ssid, HAL_MAX_SSID_LEN);
        strncpy(ap_record.passwd, passwd, HAL_MAX_PASSWD_LEN);
        memcpy(ap_record.bssid, bssid, ETH_ALEN);

        if (HAL_Kv_Set(AWSS_AP_RECORD_KEY, &ap_record, sizeof(ap_record), 0) != 0)
            break;

        memset(&ap_record, 0, sizeof(ap_record));
        len = sizeof(ap_record);
        if (HAL_Kv_Get(AWSS_AP_RECORD_KEY, &ap_record, &len) != 0)
            break;
    } while (0);

    return ret;
}

/**
 * @brief check system network is ready(get ip address) or not.
 *
 * @param None.
 * @return 0, net is not ready; 1, net is ready.
 * @see None.
 * @note None.
 */
int HAL_Sys_Net_Is_Ready()
{
    struct ifreq ifr;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock <= 0) {
        perror("socket error!\n");
        return 0;
    }

    strncpy(ifr.ifr_name, awss_dev_name, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        close(sock);
        return 0;
    }

    close(sock);
    return 1;
}

/**
 * @brief   在当前信道(channel)上以基本数据速率(1Mbps)发送裸的802.11帧(raw 802.11 frame)
 *
 * @param[in] type @n see enum HAL_Awss_frame_type, currently only FRAME_BEACON
 *                      FRAME_PROBE_REQ is used
 * @param[in] buffer @n 80211 raw frame, include complete mac header & FCS field
 * @param[in] len @n 80211 raw frame length
 * @return
   @verbatim
   =  0, send success.
   = -1, send failure.
   = -2, unsupported.
   @endverbatim
 * @see None.
 * @note awss use this API send raw frame in wifi monitor mode & station mode
 */
int HAL_Wifi_Send_80211_Raw_Frame(_IN_ enum HAL_Awss_Frame_Type type,
                                  _IN_ uint8_t *buffer, _IN_ int len)
{
    return 0;
}


/**
 * @brief   在站点(Station)模式下使能或禁用对管理帧的过滤
 *
 * @param[in] filter_mask @n see mask macro in enum HAL_Awss_frame_type,
 *                      currently only FRAME_PROBE_REQ_MASK & FRAME_BEACON_MASK is used
 * @param[in] vendor_oui @n oui can be used for precise frame match, optional
 * @param[in] callback @n see awss_wifi_mgmt_frame_cb_t, passing 80211
 *                      frame or ie to callback. when callback is NULL
 *                      disable sniffer feature, otherwise enable it.
 * @return
   @verbatim
   =  0, success
   = -1, fail
   = -2, unsupported.
   @endverbatim
 * @see None.
 * @note awss use this API to filter specific mgnt frame in wifi station mode
 */
int HAL_Wifi_Enable_Mgmt_Frame_Filter(
            _IN_ uint32_t filter_mask,
            _IN_OPT_ uint8_t vendor_oui[3],
            _IN_ awss_wifi_mgmt_frame_cb_t callback)
{
    return 0;
}

/**
 * @brief   启动一次Wi-Fi的空中扫描(Scan)
 *
 * @param[in] cb @n pass ssid info(scan result) to this callback one by one
 * @return 0 for wifi scan is done, otherwise return -1
 * @see None.
 * @note
 *      This API should NOT exit before the invoking for cb is finished.
 *      This rule is something like the following :
 *      HAL_Wifi_Scan() is invoked...
 *      ...
 *      for (ap = first_ap; ap <= last_ap; ap = next_ap){
 *        cb(ap)
 *      }
 *      ...
 *      HAL_Wifi_Scan() exit...
 */
int HAL_Wifi_Scan(awss_wifi_scan_result_cb_t cb)
{
    return 0;
}

/**
 * @brief   获取所连接的热点(Access Point)的信息
 *
 * @param[out] ssid: array to store ap ssid. It will be null if ssid is not required.
 * @param[out] passwd: array to store ap password. It will be null if ap password is not required.
 * @param[out] bssid: array to store ap bssid. It will be null if bssid is not required.
 * @return
   @verbatim
     = 0: succeeded
     = -1: failed
   @endverbatim
 * @see None.
 * @note
 *     If the STA dosen't connect AP successfully, HAL should return -1 and not touch the ssid/passwd/bssid buffer.
 */
int HAL_Wifi_Get_Ap_Info(
            _OU_ char ssid[HAL_MAX_SSID_LEN],
            _OU_ char passwd[HAL_MAX_PASSWD_LEN],
            _OU_ uint8_t bssid[ETH_ALEN])
{
    int len;
    int ret = -1;
    struct iwreq wrq;
    struct awss_ap_record_t ap_record;
    char ssid_buf[HAL_MAX_SSID_LEN + 1] = {0};

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock <= 0)
        goto GET_AP_INFO_ERR;

    strncpy(wrq.ifr_name, awss_dev_name, IFNAMSIZ);

    if (bssid) {
        if (ioctl(sock, SIOCGIWAP, &wrq) < 0)
            goto GET_AP_INFO_ERR;
        memcpy(bssid, wrq.u.ap_addr.sa_data, ETH_ALEN);
    }

    if (ssid) {
        wrq.u.essid.pointer = (caddr_t)ssid_buf;
        wrq.u.essid.length = HAL_MAX_SSID_LEN + 1;
        wrq.u.essid.flags = 0;

        if (ioctl(sock, SIOCGIWESSID, &wrq) < 0)
            goto GET_AP_INFO_ERR;

        strncpy(ssid, ssid_buf, HAL_MAX_SSID_LEN);
    }

    if (passwd) {
        memset(&ap_record, 0, sizeof(ap_record));
        len = sizeof(ap_record);
        if (HAL_Kv_Get(AWSS_AP_RECORD_KEY, &ap_record, &len) != 0)
            goto GET_AP_INFO_ERR;
        if (ssid && strcmp(ssid, ap_record.ssid) != 0)
            goto GET_AP_INFO_ERR;
        if (bssid && memcmp(bssid, ap_record.bssid, ETH_ALEN) != 0)
            goto GET_AP_INFO_ERR;
        strncpy(passwd, ap_record.passwd, HAL_MAX_PASSWD_LEN);
    }

    ret = 0;

GET_AP_INFO_ERR:
    if (sock > 0) close(sock);
    return ret;
}
