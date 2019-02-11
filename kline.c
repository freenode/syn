#include "atheme.h"
#include "pmodule.h"

#include "syn.h"

mowgli_patricia_t *ircd_klines;
mowgli_list_t ircd_wildcard_klines;
mowgli_heap_t *ircd_kline_heap;

mowgli_eventloop_timer_t *expire_timer = 0;

static void syn_m_kline(sourceinfo_t *si, int parc, char **parv);
static void syn_m_ban(sourceinfo_t *si, int parc, char **parv);
static void syn_m_unkline(sourceinfo_t *si, int parc, char **parv);
static void expire_klines(void *unused);

char *kline_kill_reason = 0;

static void mod_init(module_t *m)
{
    use_syn_main_symbols(m);

    ircd_klines = mowgli_patricia_create(noopcanon);
    ircd_kline_heap = mowgli_heap_create(sizeof(kline_t), 512, BH_NOW);

    hook_add_event("syn_kline_added");

    add_dupstr_conf_item("KLINE_KILL_REASON", &syn->conf_table, 0, &kline_kill_reason, "Banned");

    pcommand_add("KLINE", syn_m_kline, 5, MSRC_USER);
    pcommand_add("BAN", syn_m_ban, 8, MSRC_USER | MSRC_SERVER);
    pcommand_add("UNKLINE", syn_m_unkline, 3, MSRC_USER);

    expire_timer = mowgli_timer_add(base_eventloop, "expire_ircd_klines", expire_klines, NULL, 120);
}

static void mod_deinit(module_unload_intent_t intent)
{
    pcommand_delete("KLINE");
    pcommand_delete("BAN");
    pcommand_delete("UNKLINE");
    mowgli_timer_destroy(base_eventloop, expire_timer);
}

kline_t* _syn_find_kline(const char *user, const char *host)
{
    kline_t *k;
    if ((k = mowgli_patricia_retrieve(ircd_klines, host)))
        return k;

    mowgli_node_t *n;
    MOWGLI_LIST_FOREACH(n, ircd_wildcard_klines.head)
    {
        k = n->data;
        if (0 == match(k->host, host))
            return k;
        if (0 == match_ips(k->host, host))
            return k;
    }
    return NULL;
}

static void syn_add_kline(const char *setter, const char *user, const char *host, int duration, const char *reason)
{
    if (_syn_find_kline(user, host))
    {
        syn_debug(3, "Duplicate K:line %s@%s", user, host);
        return;
    }

    if (host[0] == '*' && host[1] == '\0')
    {
        wallops("%s is an idiot. Dropping *@* kline.", setter);
        return;
    }

    kline_t *k = mowgli_heap_alloc(ircd_kline_heap);
    k->duration = duration;
    k->settime = CURRTIME;
    k->expires = CURRTIME + k->duration;
    k->user = sstrdup(user);
    k->host = sstrdup(host);
    k->reason = sstrdup(reason);

    char *p;
    if (NULL != (p = strchr(k->reason, '|')))
    {
        *p = '\0';
    }

    if (strchr(k->host, '*') || strchr(k->host, '?') || (strchr(k->host, '/') && valid_ip_or_mask(k->host)))
    {
        mowgli_node_t *n = mowgli_node_create();
        mowgli_node_add(k, n, &ircd_wildcard_klines);
    }
    else
    {
        mowgli_patricia_add(ircd_klines, k->host, k);
    }

    hook_call_event("syn_kline_added", k);

    syn_debug(1, "Added K:line %s@%s (%s)", k->user, k->host, k->reason);
}

static void syn_remove_kline(const char *user, const char *host)
{
    mowgli_node_t *n, *tn;
    kline_t *k;

    kline_t *removed = mowgli_patricia_delete(ircd_klines, host);
    if (removed)
        mowgli_heap_free(ircd_kline_heap, removed);

    MOWGLI_LIST_FOREACH_SAFE(n, tn, ircd_wildcard_klines.head)
    {
        k = (kline_t*) n->data;
        if (0 == strcasecmp(k->user, user) &&
            0 == strcasecmp(k->host, host))
        {
            syn_debug(1, "Removing K:line on %s@%s", k->user, k->host);
            mowgli_node_delete(n, &ircd_wildcard_klines);
            free(k->user);
            free(k->host);
            free(k->reason);
            mowgli_heap_free(ircd_kline_heap, k);
        }
    }
}

static void expire_klines(void *unused)
{
    mowgli_node_t *n, *tn;
    kline_t *k;

    MOWGLI_LIST_FOREACH_SAFE(n, tn, ircd_wildcard_klines.head)
    {
        k = (kline_t*) n->data;

        if (k->duration == 0)
            continue;

        if (k->expires <= CURRTIME)
        {
            syn_debug(1, "Expiring K:line on %s@%s", k->user, k->host);
            mowgli_node_delete(n, &ircd_wildcard_klines);
            free(k->user);
            free(k->host);
            free(k->reason);
            mowgli_heap_free(ircd_kline_heap, k);
        }
    }

    mowgli_patricia_iteration_state_t state;
    MOWGLI_PATRICIA_FOREACH(k, &state, ircd_klines)
    {
        if (k->duration == 0)
            continue;
        if (k->expires <= CURRTIME)
        {
            syn_debug(1, "Expiring K:line on %s@%s", k->user, k->host);
            mowgli_patricia_delete(ircd_klines, k->host);
            free(k->user);
            free(k->host);
            free(k->reason);
            mowgli_heap_free(ircd_kline_heap, k);
        }
    }
}

static void _syn_vkline(const char *host, int duration, const char *reason, va_list ap)
{
/*    if (_syn_find_kline("*", host))
        return;
*/
    char buf[BUFSIZE];
    vsnprintf(buf, BUFSIZE, reason, ap);

    kline_t *k = mowgli_heap_alloc(ircd_kline_heap);
    k->duration = duration;
    k->settime = CURRTIME;
    k->expires = CURRTIME + duration;
    k->user = sstrdup("*");
    k->host = sstrdup(host);
    k->reason = sstrdup(buf);

    char *p;
    if (NULL != (p = strchr(k->reason, '|')))
    {
        *p = '\0';
    }

    if (strchr(k->host, '*') || strchr(k->host, '?') || (strchr(k->host, '/') && valid_ip_or_mask(k->host)))
    {
        mowgli_node_t *n = mowgli_node_create();
        mowgli_node_add(k, n, &ircd_wildcard_klines);
    }
    else
    {
        mowgli_patricia_add(ircd_klines, k->host, k);
    }

    kline_sts("*", "*", k->host, k->duration, k->reason);

    hook_call_event("syn_kline_added", k);

    syn_debug(1, "Added K:line %s@%s (%s)", k->user, k->host, k->reason);
}

void _syn_kline(const char *host, int duration, const char *reason, ...)
{
    va_list ap;
    va_start(ap, reason);
    _syn_vkline(host, duration, reason, ap);
    va_end(ap);
}

static void _syn_vkill(user_t *victim, const char *reason, va_list ap)
{
    char buf[BUFSIZE];
    vsnprintf(buf, BUFSIZE, reason, ap);
    notice(syn->nick, victim->nick, "%s", buf);
    kill_user(syn->me, victim, "%s", kline_kill_reason);
}


void _syn_kill(user_t *victim, const char *reason, ...)
{
    va_list ap;

    va_start(ap, reason);
    _syn_vkill(victim, reason, ap);
    va_end(ap);
}

static void _syn_vkill2(user_t *victim, const char *killreason, const char *reason, va_list ap)
{
    char buf[BUFSIZE];
    vsnprintf(buf, BUFSIZE, reason, ap);
    notice(syn->nick, victim->nick, "%s", buf);
    kill_user(syn->me, victim, "%s", killreason);
}


void _syn_kill2(user_t *victim, const char *killreason, const char *reason, ...)
{
    va_list ap;

    va_start(ap, reason);
    _syn_vkill2(victim, killreason, reason, ap);
    va_end(ap);
}

void _syn_kill_or_kline(user_t *victim, int duration, const char *reason, ...)
{
    va_list ap;
    va_start(ap, reason);
    if (!victim->ip || victim->ip[0] == '\0')
    {
        // No IP means an auth spoofed user, probably a gateway. Kill it instead.
        // Don't give away the oper reason, though.
        char user_reason[BUFSIZE];
        strncpy(user_reason, reason, sizeof(user_reason));
        char *pipe;
        if (0 != (pipe = strchr(user_reason, '|')))
            *pipe = '\0';

        _syn_vkill(victim, user_reason, ap);
    }
    else
    {
        _syn_vkline(victim->ip, duration, reason, ap);
    }
    va_end(ap);
}

static void syn_m_kline(sourceinfo_t *si, int parc, char **parv)
{
    syn_add_kline(si->su->nick, parv[2], parv[3], atoi(parv[1]), parv[4]);
}

static void syn_m_unkline(sourceinfo_t *si, int parc, char **parv)
{
    syn_remove_kline(parv[1], parv[2]);
}

static void syn_m_ban(sourceinfo_t *si, int parc, char **parv)
{
    if (parv[0][0] != 'K')
    {
        // Not a K:line; ignore
        return;
    }

    const char *user = parv[1], *host = parv[2], *setter = parv[6], *reason = parv[7];
    int duration = atoi(parv[4]); // creation = atoi(parv[3]), lifetime = atoi(parv[5]);

    if (setter[0] == '*' && si->su)
        setter = si->su->nick;

    if (duration != 0)
    {
        syn_add_kline(setter, user, host, duration, reason);
    }
    else
    {
        syn_remove_kline(user, host);
    }
}

DECLARE_MODULE_V1
(
        "syn/kline", false, mod_init, mod_deinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
