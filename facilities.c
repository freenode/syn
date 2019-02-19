#include "atheme.h"
#include "pmodule.h"

#include "syn.h"

void facility_newuser(hook_user_nick_t *data);

void syn_cmd_facility(sourceinfo_t *si, int parc, char **parv);
static void syn_facility_help(sourceinfo_t *si, const char *subcmd);

mowgli_patricia_t *syn_facility_cmds;

command_t syn_facility = { "FACILITY", N_("Inspects or modifies facility lists"), "syn:facility", 4, syn_cmd_facility, { .func = syn_facility_help } };

static void syn_cmd_facility_list(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_add(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_del(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_set(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_addbl(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_rmbl(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_show(sourceinfo_t *si, int parc, char **parv);

command_t syn_facility_list = { "LIST", N_("Displays defined facilities"), "syn:facility", 1, syn_cmd_facility_list, { .path = "syn/facility_list" } };
command_t syn_facility_add = { "ADD", N_("Configures a new facility"), "syn:facility:admin", 2, syn_cmd_facility_add, { .path = "syn/facility_add" } };
command_t syn_facility_del = { "DEL", N_("Removes a configured facility"), "syn:facility:admin", 1, syn_cmd_facility_del, { .path = "syn/facility_del" } };
command_t syn_facility_set = { "SET", N_("Modifies a configured facility"), "syn:facility:admin", 3, syn_cmd_facility_set, { .path = "syn/facility_set" } };
command_t syn_facility_addbl = { "ADDBL", N_("Adds a blacklist entry for a faciltiy"), "syn:facility", 2, syn_cmd_facility_addbl, { .path = "syn/facility_addbl" } };
command_t syn_facility_rmbl = { "RMBL", N_("Removes a blacklist entry from a facility"), "syn:facility", 2, syn_cmd_facility_rmbl, { .path = "syn/facility_rmbl" } };
command_t syn_facility_show = { "SHOW", N_("Displays information about a facility"), "syn:facility", 1, syn_cmd_facility_show, { .path = "syn/facility_show" } };

typedef enum
{
    facility_cloak_undefined,
    facility_cloak_none,
    facility_cloak_random,
    facility_cloak_hex_ident,
    facility_cloak_ident,
    facility_cloak_account,
} facility_cloak_type;

static struct {
    const char *name;
    facility_cloak_type value;
} cloak_type_map[] = {
    { "undefined", facility_cloak_undefined },
    { "none",      facility_cloak_none      },
    { "random",    facility_cloak_random    },
    { "hexip",     facility_cloak_hex_ident },
    { "ident",     facility_cloak_ident     },
    { "account",   facility_cloak_account   },
    { NULL, 0 }
};

static facility_cloak_type cloak_type_from_string(const char *name)
{
    if (name == NULL)
        return facility_cloak_undefined;

    for (int i=0; cloak_type_map[i].name != NULL; ++i)
    {
        if (0 == strcmp(name, cloak_type_map[i].name))
            return cloak_type_map[i].value;
    }
    return facility_cloak_undefined;
}

static const char *string_from_cloak_type(facility_cloak_type type)
{
    for (int i=0; cloak_type_map[i].name != NULL; ++i)
    {
        if (type == cloak_type_map[i].value)
            return cloak_type_map[i].name;
    }
    return "unknown";
}

typedef struct
{
    char hostpart[HOSTLEN];

    int blocked;
    char *blockmessage;

    char *throttlemessage;
    int throttle[2];

    facility_cloak_type cloaking;

    mowgli_list_t blacklist;

    time_t throttle_latest;
} facility_t;

typedef struct
{
    char *regex;
    atheme_regex_t *re;
} bl_entry_t;

mowgli_patricia_t *facilities;

unsigned int block_report_interval = 60;
time_t last_block_report = 0;

mowgli_heap_t *facility_heap, *blacklist_heap;

// Horrible hack to work around the race condition when
// NickServ and syn both cloak somebody.
static void on_host_change(void *vdata);

void free_facility(const char *key, void *facility, void *unused)
{
    facility_t *f = facility;

    if (f->blockmessage)
        free(f->blockmessage);
    if (f->throttlemessage)
        free(f->throttlemessage);

    mowgli_node_t *n, *tn;
    MOWGLI_LIST_FOREACH_SAFE(n, tn, f->blacklist.head)
    {
        bl_entry_t *bl = n->data;
        free(bl->regex);
        regex_destroy(bl->re);

        mowgli_heap_free(blacklist_heap, bl);

        mowgli_node_delete(n, &f->blacklist);
        mowgli_node_free(n);
    }

    mowgli_heap_free(facility_heap, f);
}

void load_facilities()
{
    FILE *f = fopen(DATADIR "/facilities.db", "r");
    if (!f)
    {
        slog(LG_DEBUG, "Couldn't open facilities list: %s", strerror(errno));
        return;
    }

    facility_t *curr_facility = NULL;

    char line[BUFSIZE];
    while (fgets(line, BUFSIZE, f))
    {
        char *token = strtok(line, " ");
        strip(token);
        if (0 == strcmp(token, "F"))
        {
            curr_facility = mowgli_heap_alloc(facility_heap);
            char *hostpart = strtok(NULL, " ");
            char *cloaking = strtok(NULL, " ");
            char *blocked = strtok(NULL, " ");
            char *throttle0 = strtok(NULL, " ");
            char *throttle1 = strtok(NULL, " ");
            strncpy(curr_facility->hostpart, hostpart, HOSTLEN);
            curr_facility->cloaking = cloak_type_from_string(cloaking);
            curr_facility->blocked = atoi(blocked);
            curr_facility->throttle[0] = atoi(throttle0);
            curr_facility->throttle[1] = atoi(throttle1);

            mowgli_patricia_add(facilities, curr_facility->hostpart, curr_facility);
            continue;
        }

        if (curr_facility == NULL)
            continue;

        if (0 == strcmp(token, "BM"))
        {
            char *msg = strtok(NULL, "");
            if (msg)
            {
                strip(msg);
                curr_facility->blockmessage = sstrdup(msg);
            }
        }
        else if (0 == strcmp(token, "TM"))
        {
            char *msg = strtok(NULL, "");
            if (msg)
            {
                strip(msg);
                curr_facility->throttlemessage = sstrdup(msg);
            }
        }
        else if (0 == strcmp(token, "BL"))
        {
            char *regex = strtok(NULL, "");
            if (!regex)
                continue;

            strip(regex);

            bl_entry_t *bl = mowgli_heap_alloc(blacklist_heap);
            bl->regex = sstrdup(regex);
            bl->re = regex_create(bl->regex, AREGEX_ICASE | AREGEX_PCRE);
            mowgli_node_add(bl, mowgli_node_create(), &curr_facility->blacklist);
        }
    }
    fclose(f);
}

void save_facilities()
{
    FILE *db = fopen(DATADIR "/facilities.db.tmp", "w");

    if (!db)
    {
        slog(LG_ERROR, "save_facilities(): cannot open facilities database for writing: %s", strerror(errno));
        return;
    }

    mowgli_patricia_iteration_state_t state;
    facility_t *f;
    MOWGLI_PATRICIA_FOREACH(f, &state, facilities)
    {
        fprintf(db, "F %s %s %d %d %d\n", f->hostpart, string_from_cloak_type(f->cloaking),
                f->blocked, f->throttle[0], f->throttle[1]);
        if (f->blockmessage)
            fprintf(db, "BM %s\n", f->blockmessage);
        if (f->throttlemessage)
            fprintf(db, "TM %s\n", f->throttlemessage);
        mowgli_node_t *n;
        MOWGLI_LIST_FOREACH(n, f->blacklist.head)
        {
            bl_entry_t *bl = n->data;
            fprintf(db, "BL %s\n", bl->regex);
        }
    }
    fclose(db);
    if (rename(DATADIR "/facilities.db.tmp", DATADIR "/facilities.db") < 0)
    {
        slog(LG_ERROR, "Couldn't rename facilities.db.tmp to facilities.db: %s", strerror(errno));
    }
}

static void mod_init(module_t *m)
{
    use_syn_main_symbols(m);
    use_syn_util_symbols(m);
    use_syn_kline_symbols(m);

    hook_add_event("user_add");
    hook_add_user_add(facility_newuser);
    hook_add_event("incoming_host_change");
    hook_add_hook("incoming_host_change", on_host_change);

    service_named_bind_command("syn", &syn_facility);

    syn_facility_cmds = mowgli_patricia_create(strcasecanon);
    command_add(&syn_facility_list, syn_facility_cmds);
    command_add(&syn_facility_add, syn_facility_cmds);
    command_add(&syn_facility_del, syn_facility_cmds);
    command_add(&syn_facility_set, syn_facility_cmds);
    command_add(&syn_facility_addbl, syn_facility_cmds);
    command_add(&syn_facility_rmbl, syn_facility_cmds);
    command_add(&syn_facility_show, syn_facility_cmds);

    facility_heap = mowgli_heap_create(sizeof(facility_t), 64, BH_NOW);
    blacklist_heap = mowgli_heap_create(sizeof(bl_entry_t), 64, BH_NOW);
    facilities = mowgli_patricia_create(strcasecanon);

    add_uint_conf_item("FACILITY_REPORT_RATE", &syn->conf_table, 0, &block_report_interval, 0, 3600, 60);

    load_facilities();
}

static void mod_deinit(module_unload_intent_t intent)
{
    save_facilities();

    del_conf_item("FACILITY_REPORT_RATE", &syn->conf_table);

    mowgli_patricia_destroy(facilities, free_facility, NULL);
    mowgli_heap_destroy(facility_heap);
    mowgli_heap_destroy(blacklist_heap);

    mowgli_patricia_destroy(syn_facility_cmds, NULL, NULL);

    service_named_unbind_command("syn", &syn_facility);

    hook_del_user_add(facility_newuser);
    hook_del_hook("incoming_host_change", on_host_change);
}

static void facility_set_cloak(user_t *u, const char * cloak)
{
    metadata_add(u, "syn:facility-cloak", cloak);

    // Check whether they've already been cloaked. If vhost contains /, vhost != host, and
    // vhost isn't unaffiliated/*, then they have a project cloak that we shouldn't override.
    char *slash = strchr(u->vhost, '/');
    if (slash != NULL && 0 != strncmp(u->vhost, "unaffiliated", slash - u->vhost) &&
            0 != strncmp(u->vhost, u->host, HOSTLEN))
        return;

    // Don't send out a no-op cloak change either
    if (strcmp(u->vhost, cloak))
        user_sethost(syn->me, u, cloak);
}

void facility_newuser(hook_user_nick_t *data)
{
    user_t *u = data->u;
    facility_t *f;
    mowgli_patricia_iteration_state_t state;

    /* If the user has already been killed, don't try to do anything */
    if (!u)
        return;

    int blocked = 0, throttled = 0, blacklisted = 0;
    char *blockmessage = NULL, *throttlemessage = NULL;
    facility_cloak_type cloak = facility_cloak_none;
    facility_t *blocking_facility = NULL, *throttling_facility = NULL;
    char *blocking_regex = NULL;

    int dospam = 0;

    MOWGLI_PATRICIA_FOREACH(f, &state, facilities)
    {
        if (0 != strncasecmp(u->host, f->hostpart, strlen(f->hostpart)))
            continue;

        syn_debug(2, "User %s matches facility %s", u->nick, f->hostpart);
        dospam = 1;
        u->flags |= SYN_UF_FACILITY_USER;

        if (f->blocked > 0)
        {
            blocked = 1;
            blocking_facility = f;
        }
        if (f->blocked < 0)
            blocked = 0;

        if (f->blockmessage)
            blockmessage = f->blockmessage;

        if (f->throttle[0] > 0 && !me.bursting)
        {
            if (f->throttle_latest < CURRTIME)
                f->throttle_latest = CURRTIME;

            f->throttle_latest += f->throttle[0];

            if (f->throttle_latest > (f->throttle[1] * f->throttle[0]) + CURRTIME)
            {
                throttled = 1;
                throttling_facility = f;
                throttlemessage = f->throttlemessage;
            }
        }

        if (f->cloaking != facility_cloak_undefined)
            cloak = f->cloaking;

        char nuh[NICKLEN+USERLEN+HOSTLEN+GECOSLEN];
        snprintf(nuh, sizeof(nuh), "%s!%s@%s %s", u->nick, u->user, u->host, u->gecos);

        mowgli_node_t *n;
        MOWGLI_LIST_FOREACH(n, f->blacklist.head)
        {
            bl_entry_t *bl = n->data;
            if (!bl->re)
                continue;
            if (regex_match(bl->re, nuh))
            {
                syn_debug(1, "User %s blacklisted in %s (%s)", u->nick, f->hostpart, bl->regex);
                blocking_facility = f;
                blocking_regex = bl->regex;
                blacklisted = 1;
                break;
            }
        }

        if (blacklisted > 0)
            break;
    }

    if (throttled)
    {
        if (last_block_report + block_report_interval < CURRTIME)
        {
            last_block_report = CURRTIME;
            syn_report("Killing user %s due to throttle [%d,%d] on facility %s",
                    u->nick, throttling_facility->throttle[0], throttling_facility->throttle[1],
                    throttling_facility->hostpart);
        }
        syn_kill2(u, "Throttled", "%s", throttlemessage);
        data->u = NULL;
        return;
    }

    if (blocked)
    {
        if (last_block_report + block_report_interval < CURRTIME)
        {
            last_block_report = CURRTIME;
            syn_report("Killing user %s; blocked by facility %s", 
                    u->nick, blocking_facility ? blocking_facility->hostpart : "(unknown)");
        }
        syn_kill2(u, "Facility Blocked", "%s", blockmessage);
        data->u = NULL;
        return;
    }

    if (blacklisted)
    {
        if (last_block_report + block_report_interval < CURRTIME)
        {
            last_block_report = CURRTIME;
            syn_report("Killing user %s; blacklisted in facility %s (%s)",
                    u->nick, blocking_facility->hostpart, blocking_regex);
        }
        syn_kill(u, "%s", blockmessage);
        data->u = NULL;
        return;
    }

    char new_vhost[HOSTLEN];
    mowgli_strlcpy(new_vhost, u->host, HOSTLEN);
    switch (cloak)
    {
        case facility_cloak_none:
        case facility_cloak_undefined:
            break;

        case facility_cloak_account:
            {
                facility_set_cloak(u, u->host);
                break;
            }

        case facility_cloak_hex_ident:
            {
                char *ipstart = strstr(new_vhost, "session");
                if (ipstart == NULL)
                {
                    syn_debug(2, "Hex IP cloaking used for %s, but I couldn't find a session marker in %s", u->nick, new_vhost);
                    break;
                }
                const char *ident = u->user;
                if (*ident == '~')
                    ++ident;
                const char *ip = decode_hex_ip(ident);

                if (ip)
                {
                    strncpy(ipstart, "ip.", new_vhost + HOSTLEN - ipstart);
                    ipstart += 3;
                    strncpy(ipstart, ip, new_vhost + HOSTLEN - ipstart);
                    facility_set_cloak(u, new_vhost);
                }
                else
                {
                    syn_report("Killing user %s; facility %s requires hexip but none was found",
                            u->nick, blocking_facility->hostpart);
                    // If we couldn't decode an IP, block the connection
                    syn_kill2(u, "No IP address supplied", "Your gateway requires an underlying IP address to be supplied, which could not be found.");
                    data->u = NULL;
                    return;
                }
                break;

            }
        case facility_cloak_ident:
            {
                char *identstart = strstr(new_vhost, "session");
                if (identstart == NULL)
                {
                    syn_debug(2, "Ident cloaking used for %s, but I couldn't find a session marker in %s", u->nick, new_vhost);
                    break;
                }

                const char *ident = u->user;
                if (*ident == '~')
                    ++ident;

                const char *suffix = encode_ident_for_host(ident);
                if (!suffix)
                {
                    syn_debug(2, "Cannot host-encode ident %s for user %s, giving up", ident, u->nick);
                    break;
                }

                strncpy(identstart, suffix, new_vhost + HOSTLEN - identstart);
                facility_set_cloak(u, new_vhost);
                break;
            }
        case facility_cloak_random:
            {
                char *randstart = strstr(new_vhost, "session");
                if (randstart == NULL)
                {
                    syn_debug(2, "Random cloaking used for %s, but I couldn't find a session marker in %s", u->nick, new_vhost);
                    break;
                }
                strncpy(randstart, get_random_host_part(u), new_vhost + HOSTLEN - randstart);
                facility_set_cloak(u, new_vhost);
                break;
            }
    }

    if (dospam && !me.bursting)
        syn_report2(2, "Allowed %s!%s@%s [%s]", u->nick, u->user, u->vhost, u->gecos);
}

static void syn_facility_help(sourceinfo_t *si, const char *subcmd)
{
    if (!subcmd)
    {
        // This can't go into one big command_success_nodata with \n in it
        // because syn defines its own sourceinfo vtable which doesn't bother
        // to split on \n in its command_success_nodata implementation
        command_success_nodata(si, _("***** \2%s Help\2 *****"), si->service->nick);
        command_success_nodata(si, _("Help for \2FACILITY\2:"));
        command_success_nodata(si, " ");
        command_success_nodata(si, "The FACILITY command displays and manipulates facility");
        command_success_nodata(si, "definitions.");
        command_success_nodata(si, " ");
        command_success_nodata(si, "A facility is roughly a related group of gateways, defined");
        command_success_nodata(si, "by a host prefix. Any new client connecting is checked");
        command_success_nodata(si, "against the list of facilities, and various actions may be");
        command_success_nodata(si, "taken based on this.");
        command_success_nodata(si, " ");
        command_success_nodata(si, "Each facility has some or all of the following information");
        command_success_nodata(si, "defined:");
        command_success_nodata(si, " ");
        command_success_nodata(si, " - The hostname prefix");
        command_success_nodata(si, " - Whether this facility is currently blocked");
        command_success_nodata(si, " - The message to send to clients blocked by this facility.");
        command_success_nodata(si, " - A throttle limit. This is of the form x,y and translates");
        command_success_nodata(si, "   rougly to y clients per x*y seconds.");
        command_success_nodata(si, " - The message to send to clients denied because of this");
        command_success_nodata(si, "   facility's throttle.");
        command_success_nodata(si, " - The cloaking scheme applied to matching clients.");
        command_success_nodata(si, " - A blacklist of regular expressions. If any of these match");
        command_success_nodata(si, "   a client that matches this facility, it will be denied.");
        command_success_nodata(si, " ");
        command_success_nodata(si, "Facilities are checked in order from least specific to most");
        command_success_nodata(si, "specific. If any facility is blocked, the client is killed,");
        command_success_nodata(si, "with the exception that a negative block value can override");
        command_success_nodata(si, "a positive one from a more general facility. If the client");
        command_success_nodata(si, "is determined to be blocked, the most specific configured");
        command_success_nodata(si, "block message is used.");
        command_success_nodata(si, " ");
        command_success_nodata(si, "The throttle settings for every matching facility are");
        command_success_nodata(si, "checked and updated, even if the client is blocked. If the");
        command_success_nodata(si, "client is denied due to throttling, the most specific");
        command_success_nodata(si, "configured throttle message is used.");
        command_success_nodata(si, " ");
        command_success_nodata(si, "For every matching facility, the client is checked against");
        command_success_nodata(si, "that facility's blacklist. If any of those regular");
        command_success_nodata(si, "expressions matches, then the client is denied, and the most");
        command_success_nodata(si, "specific block message so far encountered is used.");
        command_success_nodata(si, " ");
        command_success_nodata(si, "If the client is allowed to connect, then the cloaking");
        command_success_nodata(si, "setting is used to determine whether to modify the client's");
        command_success_nodata(si, "visible host name. Again the most specific defined value");
        command_success_nodata(si, "is used. Possible values are:");
        command_success_nodata(si, " ");
        command_success_nodata(si, " - none. Leave the client's host alone.");
        command_success_nodata(si, " - random. A 'session' marker in the client's host is");
        command_success_nodata(si, "   replaced by a random text string.");
        command_success_nodata(si, " - hexip. The user's ident is treated as a hex-encoded IP");
        command_success_nodata(si, "   address, as used by several web gateways. A 'session'");
        command_success_nodata(si, "   marker in the user's host is replaced by ");
        command_success_nodata(si, "   'ip.<decoded ip>'. If the ident cannot be decoded this");
        command_success_nodata(si, "   way, it falls back to the random method.");
        command_success_nodata(si, " - account. This is meant to be used with a sasl_usercloak");
        command_success_nodata(si, "   auth {} block and applies the host generated by the ircd");
        command_success_nodata(si, "   as gateway cloak, overriding unaffiliated cloaks.");
        command_success_nodata(si, " ");
        command_success_nodata(si, "If no matching facility has a defined cloaking method, then");
        command_success_nodata(si, "the default is \2none\2.");
        command_success_nodata(si, " ");
        command_help(si, syn_facility_cmds);
        command_success_nodata(si, " ");
        command_success_nodata(si, _("For more information, use \2/msg %s HELP FACILITY \37command\37\2."), si->service->nick);
        command_success_nodata(si, _("***** \2End of Help\2 *****"));
    }
    else
        help_display_as_subcmd(si, si->service, "FACILITY", subcmd, syn_facility_cmds);
}

void syn_cmd_facility(sourceinfo_t *si, int parc, char **parv)
{
    command_t *c;
    char *cmd = parv[0];

    if (!cmd)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FACILITY");
        command_fail(si, fault_needmoreparams, "Syntax: FACILITY LIST|ADD|DEL|SET|ADDBL|RMBL [parameters]");
        return;
    }

    c = command_find(syn_facility_cmds, cmd);
    if (c == NULL)
    {
        command_fail(si, fault_badparams, "Invalid command. Possible commands are LIST ADD DEL SET ADDBL RMBL");
        return;
    }

    command_exec(si->service, si, c, parc - 1, parv + 1);
}

void syn_cmd_facility_list(sourceinfo_t *si, int parc, char **parv)
{
    char *match = NULL;
    if (parc > 0)
        match = parv[0];

    int count = 0;
    facility_t *f;
    mowgli_patricia_iteration_state_t state;
    MOWGLI_PATRICIA_FOREACH(f, &state, facilities)
    {
        if (match && 0 != strncmp(match, f->hostpart, strlen(match)))
            continue;

        command_success_nodata(si, "[%d] %s (cloaking %s, %s, throttle %d/%d)",
                ++count, f->hostpart, string_from_cloak_type(f->cloaking),
                (f->blocked > 0 ? "blocked" : (f->blocked < 0 ? "unblocked" : "not blocked")),
                f->throttle[0], f->throttle[1]);
    }

    command_success_nodata(si, "%d facilit%s configured", count, count == 1 ? "y" : "ies");
}

void syn_cmd_facility_add(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 1)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FACILITY ADD");
        command_fail(si, fault_needmoreparams, "Syntax: FACILITY ADD <hostpart> [cloaktype]");
        return;
    }

    const char *hostpart = parv[0];
    facility_cloak_type cloak = cloak_type_from_string(parc > 1 ? parv[1] : NULL);

    facility_t *f = mowgli_heap_alloc(facility_heap);
    strncpy(f->hostpart, hostpart, HOSTLEN);
    f->cloaking = cloak;

    mowgli_patricia_add(facilities, f->hostpart, f);

    syn_report("\002FACILITY ADD\002 %s by %s", f->hostpart, get_oper_name(si));

    command_success_nodata(si, "Added facility %s", f->hostpart);

    save_facilities();
}

void syn_cmd_facility_del(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 1)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FACILITY DEL");
        command_fail(si, fault_needmoreparams, "Syntax: FACILITY DEL <hostpart>");
        return;
    }

    facility_t *f = mowgli_patricia_retrieve(facilities, parv[0]);

    if (f == NULL)
    {
        command_fail(si, fault_badparams, "No such facility %s was found.", parv[0]);
        return;
    }

    free_facility(NULL, f, NULL);
    mowgli_patricia_delete(facilities, parv[0]);

    syn_report("\002FACILITY DEL\002 %s by %s", parv[0], get_oper_name(si));

    command_success_nodata(si, "Facility %s deleted", parv[0]);

    save_facilities();
}



void syn_cmd_facility_set(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 3)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FACILITY SET");
        command_fail(si, fault_needmoreparams, "Syntax: FACILITY SET <hostpart> <setting> [arguments]");
        return;
    }

    facility_t *f = mowgli_patricia_retrieve(facilities, parv[0]);
    if (f== NULL)
    {
        command_fail(si, fault_badparams, "No such facility %s", parv[0]);
        return;
    }

    if (0 == strcasecmp(parv[1], "cloaking"))
    {
        facility_cloak_type cloak = cloak_type_from_string(parv[2]);
        f->cloaking = cloak;

        syn_report("\002FACILITY SET\002 cloaking->%s for %s by %s",
                string_from_cloak_type(cloak), f->hostpart, get_oper_name(si));
        command_success_nodata(si, "Cloaking method for %s set to %s", f->hostpart, string_from_cloak_type(cloak));

        save_facilities();
        return;
    }

    if (0 == strcasecmp(parv[1], "blocked"))
    {
        if (parc < 3)
            f->blocked = 0;
        else
            f->blocked = atoi(parv[2]);

        syn_report("\002FACILITY SET\002 blocked->%d for %s by %s",
                f->blocked, f->hostpart, get_oper_name(si));
        command_success_nodata(si, "Blocked for %s was set to %d", f->hostpart, f->blocked);

        save_facilities();
        return;
    }

    if (0 == strcasecmp(parv[1], "throttle"))
    {
        char buf[32];
        strncpy(buf, parv[2], 32);
        char *p = strchr(buf, ',');

        if (p == NULL)
        {
            command_fail(si, fault_badparams, STR_INVALID_PARAMS, "FACILITY SET THROTTLE");
            command_fail(si, fault_badparams, "Syntax: FACILITY SET <name> THROTTLE n,m");
            return;
        }
        *p++ = '\0';

        f->throttle[0] = atoi(buf);
        f->throttle[1] = atoi(p);

        syn_report("\002FACILITY SET\002 throttle->%d/%d for %s by %s",
                f->throttle[0], f->throttle[1], f->hostpart, get_oper_name(si));
        command_success_nodata(si, "Throttle for %s was set to %d seconds, burst %d",
                f->hostpart, f->throttle[0], f->throttle[1]);

        save_facilities();
        return;
    }

    if (0 == strcasecmp(parv[1], "blockmessage"))
    {
        if (f->blockmessage)
            free(f->blockmessage);

        if (0 == strcmp(parv[2], "-"))
            f->blockmessage = NULL;
        else
            f->blockmessage = sstrdup(parv[2]);

        syn_report("\002FACILITY SET\002 block message->%s for %s by %s",
                f->blockmessage, f->hostpart, get_oper_name(si));
        command_success_nodata(si, "Block message for %s was set to %s", f->hostpart, f->blockmessage);

        save_facilities();
        return;
    }

    if (0 == strcasecmp(parv[1], "throttlemessage"))
    {
        if (f->throttlemessage)
            free(f->throttlemessage);

        if (0 == strcmp(parv[2], "-"))
            f->throttlemessage = NULL;
        else
            f->throttlemessage = sstrdup(parv[2]);

        syn_report("\002FACILITY SET\002 throttle message->%s for %s by %s",
                f->throttlemessage, f->hostpart, get_oper_name(si));
        command_success_nodata(si, "Throttle message for %s was set to %s", f->hostpart, f->throttlemessage);

        save_facilities();
        return;
    }

    command_fail(si, fault_badparams, "Unknown setting name");
}



void syn_cmd_facility_addbl(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 2)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FACILITY ADDBL");
        command_fail(si, fault_needmoreparams, "Syntax: FACILITY ADDBL <hostpart> <regex>");
        return;
    }

    facility_t *f = mowgli_patricia_retrieve(facilities, parv[0]);
    if (f== NULL)
    {
        command_fail(si, fault_badparams, "No such facility %s", parv[0]);
        return;
    }

    bl_entry_t *bl = mowgli_heap_alloc(blacklist_heap);
    bl->regex = sstrdup(parv[1]);
    bl->re = regex_create(bl->regex, AREGEX_ICASE | AREGEX_PCRE);

    if (! bl->re)
    {
        command_fail(si, fault_badparams, "Failed to compile regex \"%s\"", bl->regex);
        return;
    }

    mowgli_node_add(bl, mowgli_node_create(), &f->blacklist);

    syn_report("\002FACILITY ADDBL\002 %s to %s by %s", bl->regex, f->hostpart, get_oper_name(si));
    command_success_nodata(si, "Added blacklist \"%s\" for %s", bl->regex, f->hostpart);

    save_facilities();
}



void syn_cmd_facility_rmbl(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 2)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FACILITY RMBL");
        command_fail(si, fault_needmoreparams, "Syntax: FACILITY RMBL <hostpart> <regex>");
        return;
    }

    facility_t *f = mowgli_patricia_retrieve(facilities, parv[0]);
    if (f== NULL)
    {
        command_fail(si, fault_badparams, "No such facility %s", parv[0]);
        return;
    }

    mowgli_node_t *n, *tn;
    MOWGLI_LIST_FOREACH_SAFE(n, tn, f->blacklist.head)
    {
        bl_entry_t *bl = n->data;
        if (0 != strcmp(parv[1], bl->regex))
            continue;

        free(bl->regex);
        regex_destroy(bl->re);

        mowgli_heap_free(blacklist_heap, bl);

        mowgli_node_delete(n, &f->blacklist);
        mowgli_node_free(n);

        syn_report("\002FACILITY RMBL\002 %s from %s by %s", parv[1], f->hostpart, get_oper_name(si));
        command_success_nodata(si, "Removed blacklist \"%s\" from %s", parv[1], f->hostpart);
    }

    save_facilities();
}

void syn_cmd_facility_show(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 1)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FACILITY SHOW");
        command_fail(si, fault_needmoreparams, "Syntax: FACILITY SHOW <hostpart>");
        return;
    }

    facility_t *f = mowgli_patricia_retrieve(facilities, parv[0]);
    if (f== NULL)
    {
        command_fail(si, fault_badparams, "No such facility %s", parv[0]);
        return;
    }

    command_success_nodata(si, "Facility %s:", f->hostpart);
    command_success_nodata(si, "  cloaking method: %s", string_from_cloak_type(f->cloaking));
    command_success_nodata(si, "  %s, block message \"%s\"",
            f->blocked > 0 ? "blocked" : ( f->blocked < 0 ? "unblocked" : "not blocked"),
            f->blockmessage);
    command_success_nodata(si, "  Throttle rate %d/%d, throttle message \"%s\"",
            f->throttle[0], f->throttle[1], f->throttlemessage);

    command_success_nodata(si, "Blacklist:");

    int count = 0;
    mowgli_node_t *n;
    MOWGLI_LIST_FOREACH(n, f->blacklist.head)
    {
        bl_entry_t *bl = n->data;
        command_success_nodata(si, "[%d] %s", ++count, bl->regex);
    }
    command_success_nodata(si, "%d blacklist entries for %s", count, f->hostpart);
}

static void on_host_change(void *vdata)
{
    hook_incoming_host_change_t *data = vdata;

    metadata_t *md = metadata_find(data->user, "syn:facility-cloak");
    if (!md)
        return;

    if ((0 == strncmp(data->user->vhost, "unaffiliated/", 13) && 0 != strncmp(data->oldvhost, "nat/", 4)) ||
        0 == strncmp(data->user->vhost, data->user->host, HOSTLEN))
    {
        // Override the host change -- a facility cloak is being replaced by unaffiliated, or a facility by
        // another facility (this happens when removing a nickserv account vhost while a gateway user is logged in)
        strshare_unref(data->user->vhost);
        data->user->vhost = strshare_get(md->value);
    }
    else
    {
        // Bounce the sethost, to fix the race condition where services and syn both set a vhost on connect.
    }
    sethost_sts(syn->me, data->user, data->user->vhost);
}

DECLARE_MODULE_V1
(
        "syn/facilities", false, mod_init, mod_deinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
