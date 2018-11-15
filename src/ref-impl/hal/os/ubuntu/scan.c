#include <net/if.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>

#include "nl80211.h"
#include "iw.h"
#include "iot_import.h"

#define AWSS_MAC_STR             "%02X:%02X:%02X:%02X:%02X:%02X"
#define AWSS_MAC2STR(mac)        (((char *)(mac))[0]) & 0xFF, (((char *)(mac))[1]) & 0xFF, (((char *)(mac))[2]) & 0xFF,\
                                 (((char *)(mac))[3]) & 0xFF, (((char *)(mac))[4]) & 0xFF, (((char *)(mac))[5])

struct scan_params {
    bool unknown;
    enum print_ie_type type;
    bool show_both_ie_sets;
};

static awss_wifi_scan_result_cb_t g_scan_cb;
int awss_set_scan_cb(awss_wifi_scan_result_cb_t cb)
{
    g_scan_cb = cb;
    return 0;
}

int parse_sched_scan(struct nl_msg *msg, int *argc, char ***argv)
{
    int err = -ENOMEM;
    struct nl_msg *ssids = NULL;

    ssids = nlmsg_alloc();
    if (!ssids)
        return -ENOMEM;

    NLA_PUT(ssids, 1, 0, "");
    nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);

    err = 0;

nla_put_failure:
    nlmsg_free(ssids);

    return err;
}

static int handle_scan(struct nl80211_state *state,
               struct nl_msg *msg,
               int argc, char **argv,
               enum id_input id)
{
    struct nl_msg *ssids = NULL;
    int err = -ENOMEM;

    ssids = nlmsg_alloc();
    if (!ssids)
        return -ENOMEM;

    NLA_PUT(ssids, 1, 0, "");
    nla_put_nested(msg, NL80211_ATTR_SCAN_SSIDS, ssids);
#if 0
    do {
        int flags = 0;
        flags |= NL80211_SCAN_FLAG_FILS_MAX_CHANNEL_TIME;
        flags |= NL80211_SCAN_FLAG_ACCEPT_BCAST_PROBE_RESP;
        NLA_PUT_U32(msg, NL80211_ATTR_SCAN_FLAGS, flags);
    } while (0);
#endif

    err = 0;

nla_put_failure:
    nlmsg_free(ssids);

    return err;
}

int ieee80211_frequency_to_channel(int freq)
{
    /* see 802.11-2007 17.3.8.3.2 and Annex J */
    if (freq == 2484)
        return 14;
    else if (freq < 2484)
        return (freq - 2407) / 5;
    else if (freq >= 4910 && freq <= 4980)
        return (freq - 4000) / 5;
    else if (freq <= 45000) /* DMG band lower limit */
        return (freq - 5000) / 5;
    else if (freq >= 58320 && freq <= 64800)
        return (freq - 56160) / 2160;
    else
        return 0;
}

static int print_bss_idx = 0;

static int print_bss_handler(struct nl_msg *msg, void *arg)
{
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    static struct nla_policy bss_policy[NL80211_BSS_MAX + 1] = {
        [NL80211_BSS_FREQUENCY] = { .type = NLA_U32 },
        [NL80211_BSS_BSSID] = { },
        [NL80211_BSS_INFORMATION_ELEMENTS] = { },
        [NL80211_BSS_SIGNAL_MBM] = { .type = NLA_U32 },
        [NL80211_BSS_BEACON_IES] = { },
    };
    uint8_t *ies = NULL;
    int ielen = 0;

    char ssid[HAL_MAX_SSID_LEN] = {0};
    uint8_t bssid[ETH_ALEN] = {0};
    signed char rssi = -1;
    uint8_t chan = 0;

    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
          genlmsg_attrlen(gnlh, 0), NULL);

    if (!tb[NL80211_ATTR_BSS]) {
        fprintf(stderr, "bss info missing!\n");
        return NL_SKIP;
    }
    if (nla_parse_nested(bss, NL80211_BSS_MAX,
                 tb[NL80211_ATTR_BSS],
                 bss_policy)) {
        fprintf(stderr, "failed to parse nested attributes!\n");
        return NL_SKIP;
    }

    if (!bss[NL80211_BSS_BSSID])
        return NL_SKIP;

    memcpy(bssid, nla_data(bss[NL80211_BSS_BSSID]), ETH_ALEN);

    if (bss[NL80211_BSS_FREQUENCY]) {
        chan = ieee80211_frequency_to_channel(nla_get_u32(bss[NL80211_BSS_FREQUENCY]));
    }

    if (bss[NL80211_BSS_SIGNAL_MBM]) {
        rssi = nla_get_u32(bss[NL80211_BSS_SIGNAL_MBM]);
        if (rssi > 0) rssi = rssi - 256;
        if (rssi == 0) rssi = -1;
    }

    if (bss[NL80211_BSS_BEACON_IES]) {
        ies = nla_data(bss[NL80211_BSS_BEACON_IES]);
        ielen = nla_len(bss[NL80211_BSS_BEACON_IES]);
    } else if (bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
        ies = nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
        ielen = nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]);
    }

    while (ielen >= 2 && ielen >= ies[1]) {
        switch (ies[0]) {
            case 0:
                strncpy(ssid, (const char *)ies + 2, ies[1]);
                break;
            case 3:
                chan = ies[2];
                break;
        }
        ielen -= ies[1] + 2;
        ies += ies[1] + 2;
    }

    if (g_scan_cb) g_scan_cb(ssid, bssid, 0, 0, chan, rssi, 0);

    return NL_SKIP;
}

static struct scan_params scan_params;

static int handle_scan_dump(struct nl80211_state *state,
                struct nl_msg *msg,
                int argc, char **argv,
                enum id_input id)
{
    if (argc > 1)
        return 1;

    memset(&scan_params, 0, sizeof(scan_params));

    scan_params.show_both_ie_sets = true;
    scan_params.type = PRINT_SCAN;

    register_handler(print_bss_handler, &scan_params);
    return 0;
}

static int handle_scan_combined(struct nl80211_state *state,
                struct nl_msg *msg,
                int argc, char **argv,
                enum id_input id)
{
    char **trig_argv;
    static char *dump_argv[] = {
        NULL,
        "scan",
        "dump",
        NULL,
    };
    static const uint32_t cmds[] = {
        NL80211_CMD_NEW_SCAN_RESULTS,
        NL80211_CMD_SCAN_ABORTED,
    };
    int trig_argc, dump_argc, err;
    int i;

    print_bss_idx = 0;

    dump_argc = 3;

    trig_argc = 3 + (argc - 2) + (3 - dump_argc);
    trig_argv = calloc(trig_argc, sizeof(*trig_argv));
    if (!trig_argv)
        return -ENOMEM;
    trig_argv[0] = argv[0];
    trig_argv[1] = "scan";
    trig_argv[2] = "trigger";

    for (i = 0; i < argc - 2 - (dump_argc - 3); i++)
        trig_argv[i + 3] = argv[i + 2 + (dump_argc - 3)];
    err = handle_cmd(state, id, trig_argc, trig_argv);
    free(trig_argv);
    if (err)
        return err;

    /*
     * WARNING: DO NOT COPY THIS CODE INTO YOUR APPLICATION
     *
     * This code has a bug, which requires creating a separate
     * nl80211 socket to fix:
     * It is possible for a NL80211_CMD_NEW_SCAN_RESULTS or
     * NL80211_CMD_SCAN_ABORTED message to be sent by the kernel
     * before (!) we listen to it, because we only start listening
     * after we send our scan request.
     *
     * Doing it the other way around has a race condition as well,
     * if you first open the events socket you may get a notification
     * for a previous scan.
     *
     * The only proper way to fix this would be to listen to events
     * before sending the command, and for the kernel to send the
     * scan request along with the event, so that you can match up
     * whether the scan you requested was finished or aborted (this
     * may result in processing a scan that another application
     * requested, but that doesn't seem to be a problem).
     *
     * Alas, the kernel doesn't do that (yet).
     */
    if (listen_events(state, ARRAY_SIZE(cmds), cmds) ==
                    NL80211_CMD_SCAN_ABORTED) {
        printf("scan aborted!\n");
        return 0;
    }

    dump_argv[0] = argv[0];
    return handle_cmd(state, id, dump_argc, dump_argv);
}
TOPLEVEL(scan, "[-u] [freq <freq>*] [duration <dur>] [ies <hex as 00:11:..>] [meshid <meshid>] [lowpri,flush,ap-force,duration-mandatory] [randomise[=<addr>/<mask>]] [ssid <ssid>*|passive]", 0, 0,
     CIB_NETDEV, handle_scan_combined,
     "Scan on the given frequencies and probe for the given SSIDs\n"
     "(or wildcard if not given) unless passive scanning is requested.\n"
     "If -u is specified print unknown data in the scan results.\n"
     "Specified (vendor) IEs must be well-formed.");
COMMAND(scan, dump, "[-u]",
    NL80211_CMD_GET_SCAN, NLM_F_DUMP, CIB_NETDEV, handle_scan_dump,
    "Dump the current scan results. If -u is specified, print unknown\n"
    "data in scan results.");
COMMAND(scan, trigger, "[freq <freq>*] [duration <dur>] [ies <hex as 00:11:..>] [meshid <meshid>] [lowpri,flush,ap-force,duration-mandatory] [randomise[=<addr>/<mask>]] [ssid <ssid>*|passive]",
    NL80211_CMD_TRIGGER_SCAN, 0, CIB_NETDEV, handle_scan,
     "Trigger a scan on the given frequencies with probing for the given\n"
     "SSIDs (or wildcard if not given) unless passive scanning is requested.\n"
     "Duration(in TUs), if specified, will be used to set dwell times.\n");
