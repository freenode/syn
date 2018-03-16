#include "atheme.h"
#include "uplink.h"

#include "syn.h"

static void check_user(hook_user_nick_t *data, bool isnewuser);
static bool maybe_kline_user_host(user_t *u, const char *hostname);

typedef struct
{
    user_t *u;
    sockaddr_any_t sa;
    dns_query_t dns_query;
} reverse_lookup_client;

mowgli_heap_t *rlc_heap;

static void start_reverse_lookup(user_t *u, const char *ip);
static void reverse_lookup_callback(void *vptr, dns_reply_t *reply);
static void free_rlc_info(user_t *u);
static void abort_rlc(user_t *u);

static void check_all_users(void *v)
{
    user_t *u;
    mowgli_patricia_iteration_state_t state;

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        hook_user_nick_t data = { .u = u };
        check_user(&data, false);
    }
}

static void gateway_newuser(hook_user_nick_t *data)
{
    check_user(data, true);
}

static void mod_init(module_t *m)
{
    use_syn_main_symbols(m);
    use_syn_util_symbols(m);
    use_syn_kline_symbols(m);

    hook_add_event("user_add");
    hook_add_user_add(gateway_newuser);
    hook_add_event("syn_kline_added");
    hook_add_hook("syn_kline_added", check_all_users);
    hook_add_event("syn_kline_check");

    hook_add_event("user_delete");
    hook_add_user_delete(abort_rlc);
    rlc_heap = mowgli_heap_create(sizeof(rlc_heap), 512, BH_NOW);

    check_all_users(NULL);
}

static void mod_deinit(module_unload_intent_t intent)
{
    hook_del_user_add(gateway_newuser);
    hook_del_hook("syn_kline_added", check_all_users);

    mowgli_heap_destroy(rlc_heap);
    hook_del_user_delete(abort_rlc);
}

static bool maybe_kline_user_host(user_t *u, const char *hostname)
{
    kline_t *k = syn_find_kline(NULL, hostname);

    if (k)
    {
        syn_report("Killing user %s; reported host [%s] matches K:line [%s@%s] (%s)",
                u->nick, hostname, k->user, k->host, k->reason);
        syn_kill(u, "Your reported hostname [%s] is banned: %s", hostname, k->reason);
        return true;
    }

    return false;
}

static void check_user(hook_user_nick_t *data, bool isnewuser)
{
    user_t *u = data->u;

    /* If the user has already been killed, don't try to do anything */
    if (!u)
        return;

    // If they've been marked as not having a decodeable IP address, don't try again.
    if (u->flags & SYN_UF_NO_GATEWAY_IP)
        return;

    const char *ident = u->user;
    if (*ident == '~')
        ++ident;

    const char *identhost = decode_hex_ip(ident);

    if (identhost)
    {
        if (maybe_kline_user_host(u, identhost))
        {
            data->u = NULL;
            return;
        }

        // Ident not K:lined(yet); check whether it should be
        // Note that this happens after the K:line check; if this hook adds a
        // new kline, then we'll be called again through the syn_kline_add hook
        syn_kline_check_data_t d = { identhost, u, 0 };
        hook_call_event("syn_kline_check", &d);

        // If a kline was added by this, then we got called again and have already killed the user if we should.
        // Don't do any more.
        if (d.added)
        {
            // On the off-chance that a kline was added that doesn't in fact kill this user, this will cause
            // subsequent checks (facilities etc) to be skipped. That's better than crashing or running amok
            // because we tried to gateway-cloak an already-dead user, though.
            data->u = NULL;
            return;
        }

        if (isnewuser)
        {
                // They weren't already K:lined, and we didn't K:line them. BOPM may want to, though...
                sts(":%s ENCAP * SNOTE F :Client connecting: %s (%s@%s) [%s] {%s} [%s]",
                                ME, u->nick, u->user, u->host, identhost, "?", u->gecos);
        }
    }
    else
    {
        // Performance hack: if we can't decode a hex IP, assume that this user is not connecting through a
        // gateway that makes any attempt to identify them, and skip them for all future checks.
        u->flags |= SYN_UF_NO_GATEWAY_IP;
        return;
    }

    char gecos[GECOSLEN];
    strncpy(gecos, u->gecos, GECOSLEN);
    char *p = strchr(gecos, ' ');
    if (p != NULL)
        *p = '\0';

    p = strchr(gecos, '/');
    if (p != NULL)
        *p++ = '\0';

    if (maybe_kline_user_host(u, gecos))
    {
        data->u = NULL;
        return;
    }
    else if (p && maybe_kline_user_host(u, p))
    {
        data->u = NULL;
        return;
    }

#if 0
    if (!p)
    {
        syn_debug(3, "no hostname found for %s!%s@%s[%s]; doing reverse lookup", u->nick, u->user, u->host, u->gecos);

        // There was no hostname, only an IP. This can happen when the hostname is too long to fit in a gecos field.
        // Do a reverse lookup and see whether the hostname is also klined.
        start_reverse_lookup(u, identhost);
    }
#endif

    // As above, but for gecos hostnames
    syn_kline_check_data_t d = { gecos, u };
    hook_call_event("syn_kline_check", &d);
    d.ip = p;
    hook_call_event("syn_kline_check", &d);
}

// Reverse DNS lookup stuff below here

static void start_reverse_lookup(user_t *u, const char *ip)
{
    reverse_lookup_client *rlc = mowgli_heap_alloc(rlc_heap);

    rlc->u = u;
    rlc->dns_query.ptr = rlc;
    rlc->dns_query.callback = reverse_lookup_callback;

    if (0 == inet_aton(ip, &rlc->sa.sin.sin_addr))
    {
        syn_debug(3, "failed to convert ip address [%s] for user [%s]", ip, u->nick);
        mowgli_heap_free(rlc_heap, rlc);
        return;
    }

    rlc->sa.sa.sa_family = AF_INET;

    syn_debug(3, "starting reverse lookup on [%s] for user [%s]", ip, u->nick);

    gethost_byaddr(&rlc->sa, &rlc->dns_query);

    free_rlc_info(u);
    privatedata_set(u, "syn:gateway:rlcinfo", rlc);
}

static void free_rlc_info(user_t *u)
{
    reverse_lookup_client *rlc = privatedata_get(u, "syn:gateway:rlcinfo");
    if (!rlc)
        return;

    mowgli_heap_free(rlc_heap, rlc);
    privatedata_set(u, "syn:gateway:rlcinfo", 0);
}

static void abort_rlc(user_t *u)
{
    // User quit. If a reverse lookup is pending, blank out the user pointer to avoid crashing when it completes
    reverse_lookup_client *rlc = privatedata_get(u, "syn:gateway:rlcinfo");
    if (!rlc)
        return;

    rlc->u = NULL;
}

static void reverse_lookup_callback(void *vptr, dns_reply_t *reply)
{
    reverse_lookup_client *rlc = vptr;
    user_t *u = rlc->u;

    if (!u)
    {
        // User quit, and abort_rlc() blanked out the u pointer for us
        return;
    }

    // Whether there's a kline or not, we're done with this info.
    free_rlc_info(u);

    if (!reply)
    {
        syn_debug(3, "got lookup callback with no reply for user [%s]", u->nick);
        return;
    }

    syn_debug(3, "got reverse lookup info [%s] for user [%s]", reply->h_name, u->nick);

    maybe_kline_user_host(u, reply->h_name);
}

DECLARE_MODULE_V1
(
        "syn/gateways", false, mod_init, mod_deinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
