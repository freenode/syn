#include "atheme.h"

static void syn_handler(sourceinfo_t *si, int parc, char *parv[]);
static void syn_join_channel(void *unused);

service_t *syn;

struct
{
    char *channel;
    char *debugchannel;
    unsigned int debug;
    unsigned int verbosity;
} syn_config;

static void mod_init(module_t *m)
{
//  command_add(&syn_help, &syn_cmdtree);

    syn = service_add("syn", syn_handler);
    service_set_chanmsg(syn, true);

    hook_add_event("config_ready");
    hook_add_config_ready((void(*)(void*))syn_join_channel);
    hook_add_server_eob((void(*)(server_t*))syn_join_channel);

    add_dupstr_conf_item("CHANNEL", &syn->conf_table, 0, &syn_config.channel, 0);
    add_dupstr_conf_item("DEBUGCHANNEL", &syn->conf_table, 0, &syn_config.debugchannel, 0);
    add_uint_conf_item("DEBUG", &syn->conf_table, 0, &syn_config.debug, 0, 15, 0);
    add_uint_conf_item("VERBOSE", &syn->conf_table, 0, &syn_config.verbosity, 0, 15, 0);
}

static void mod_deinit(module_unload_intent_t intent)
{
//  command_delete(&syn_help, &syn_cmdtree);

    del_conf_item("CHANNEL", &syn->conf_table);
    del_conf_item("DEBUGCHANNEL", &syn->conf_table);
    del_conf_item("DEBUG", &syn->conf_table);
    del_conf_item("VERBOSE", &syn->conf_table);

    hook_del_config_ready((void(*)(void*))syn_join_channel);
    hook_del_server_eob((void(*)(server_t*))syn_join_channel);

    service_delete(syn);
}

static void syn_cmd_success_nodata(sourceinfo_t *si, const char *text)
{
    if (si->c)
        notice_channel_sts(si->service->me, si->c, text);
    else
        notice_user_sts(si->service->me, si->su, text);
}


static void syn_cmd_success_string(sourceinfo_t *si, const char *string, const char *text)
{
    if (si->c)
        notice_channel_sts(si->service->me, si->c, text);
    else
        notice_user_sts(si->service->me, si->su, text);
}


static void syn_cmd_fail(sourceinfo_t *si, cmd_faultcode_t fault, const char *text)
{
    if (si->c)
        notice_channel_sts(si->service->me, si->c, text);
    else
        notice_user_sts(si->service->me, si->su, text);
}

struct sourceinfo_vtable syn_si_vtable = {
    .description        = "syn",
    .cmd_fail           = syn_cmd_fail,
    .cmd_success_nodata = syn_cmd_success_nodata,
    .cmd_success_string = syn_cmd_success_string,
};


static void syn_handler(sourceinfo_t *si, int parc, char *parv[])
{
    char *cmd;
    char *text;
    char orig[BUFSIZE];

    /* this should never happen */
    if (parv[0][0] == '&')
    {
        slog(LG_ERROR, "services(): got parv with local channel: %s", parv[0]);
        return;
    }

    /* make a copy of the original for debugging */
    mowgli_strlcpy(orig, parv[parc - 1], BUFSIZE);

    // Is this a message to a channel?
    if (parv[0][0] == '#')
    {
        if (!syn_config.channel || 0 != strcmp(syn_config.channel, parv[0]))
            return;

        char *firstarg = strtok(parv[parc-1], " ");
        if (!firstarg || 0 != strncmp(si->service->nick, firstarg, strlen(si->service->nick)))
            return;

        si->c = channel_find(parv[0]);

        cmd = strtok(NULL, " ");
        text = strtok(NULL, "");
    }
    else
    {
        cmd = strtok(parv[parc - 1], " ");
        text = strtok(NULL, "");
    }

    if (!cmd)
        return;
    if (*cmd == '\001')
    {
        handle_ctcp_common(si, cmd, text);
        return;
    }

    si->v = &syn_si_vtable;

    /* take the command through the hash table */
    command_exec_split(si->service, si, cmd, text, syn->commands);
}

static void syn_join_channel(void *unused)
{
    if (syn_config.channel && me.connected)
        join(syn_config.channel, syn->nick);
    if (syn_config.debugchannel && me.connected)
        join(syn_config.debugchannel, syn->nick);
}

void syn_debug(int debuglevel, char *fmt, ...)
{
    if (debuglevel > syn_config.debug)
        return;

    va_list ap;
    char buf[BUFSIZE];

    char *debugchannel = syn_config.debugchannel;

    if (!debugchannel)
        debugchannel = syn_config.channel;

    if (!debugchannel)
        return;

    if (!channel_find(debugchannel))
        return;

    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZE, fmt, ap);
    va_end(ap);

    msg(syn->nick, debugchannel, "[debug%d] %s", debuglevel, buf);
}

void syn_vreport(char *fmt, va_list ap)
{
    char buf[BUFSIZE];

    if (!syn_config.channel)
        return;

    if (!channel_find(syn_config.channel))
        return;

    vsnprintf(buf, BUFSIZE, fmt, ap);

    msg(syn->nick, syn_config.channel, "%s", buf);
}

void syn_report(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    syn_vreport(fmt, ap);
    va_end(ap);
}

void syn_report2(unsigned int level, char *fmt, ...)
{
    if (syn_config.verbosity < level)
        return;

    va_list ap;
    va_start(ap, fmt);
    syn_vreport(fmt, ap);
    va_end(ap);
}

DECLARE_MODULE_V1
(
        "syn/main", false, mod_init, mod_deinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
