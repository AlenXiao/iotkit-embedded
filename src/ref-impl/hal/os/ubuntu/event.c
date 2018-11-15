#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <errno.h>
#include <inttypes.h>
#include "iw.h"

static int no_seq_check(struct nl_msg *msg, void *arg)
{
    return NL_OK;
}

struct wait_event {
    int n_cmds;
    const uint32_t *cmds;
    uint32_t cmd;
    struct print_event_args *pargs;
};

static int wait_event(struct nl_msg *msg, void *arg)
{
    struct wait_event *wait = arg;
    struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
    int i;

    for (i = 0; i < wait->n_cmds; i++) {
        if (gnlh->cmd == wait->cmds[i]) {
            wait->cmd = gnlh->cmd;
        }
    }

    return NL_SKIP;
}

int __prepare_listen_events(struct nl80211_state *state)
{
    int mcid, ret;

    /* Scan multicast group */
    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "scan");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }

    /* MLME multicast group */
    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "mlme");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }

    mcid = nl_get_multicast_id(state->nl_sock, "nl80211", "vendor");
    if (mcid >= 0) {
        ret = nl_socket_add_membership(state->nl_sock, mcid);
        if (ret)
            return ret;
    }

    return 0;
}

uint32_t __do_listen_events(struct nl80211_state *state,
             const int n_waits, const uint32_t *waits,
             struct print_event_args *args)
{
    struct nl_cb *cb = nl_cb_alloc(NL_CB_DEFAULT);
    struct wait_event wait_ev;

    if (!cb) {
        fprintf(stderr, "failed to allocate netlink callbacks\n");
        return -ENOMEM;
    }

    /* no sequence checking for multicast messages */
    nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);
    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, NULL);

    if (n_waits && waits) {
        wait_ev.cmds = waits;
        wait_ev.n_cmds = n_waits;
        wait_ev.pargs = args;
        register_handler(wait_event, &wait_ev);
    }

    wait_ev.cmd = 0;

    while (!wait_ev.cmd)
        nl_recvmsgs(state->nl_sock, cb);

    nl_cb_put(cb);

    return wait_ev.cmd;
}

uint32_t listen_events(struct nl80211_state *state,
            const int n_waits, const uint32_t *waits)
{
    int ret;

    ret = __prepare_listen_events(state);
    if (ret)
        return ret;

    return __do_listen_events(state, n_waits, waits, NULL);
}
