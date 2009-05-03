#include "atheme.h"

#include "syn.h"

DECLARE_MODULE_V1
(
        "syn/facilities", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

void facility_newuser(void *v);

void syn_cmd_facility(sourceinfo_t *si, int parc, char **parv);

list_t syn_facility_cmds;

command_t syn_facility = { "FACILITY", N_("Inspects or modifies facility lists"), "syn:facility", 4, syn_cmd_facility };

static void syn_cmd_facility_list(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_add(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_del(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_set(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_addbl(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_rmbl(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_facility_show(sourceinfo_t *si, int parc, char **parv);

command_t syn_facility_list = { "LIST", N_("Displays defined facilities"), "syn:facility", 1, syn_cmd_facility_list };
command_t syn_facility_add = { "ADD", N_("Configures a new facility"), "syn:facility:admin", 2, syn_cmd_facility_add };
command_t syn_facility_del = { "DEL", N_("Removes a configured facility"), "syn:facility:admin", 1, syn_cmd_facility_del };
command_t syn_facility_set = { "SET", N_("Modifies a configured facility"), "syn:facility:admin", 3, syn_cmd_facility_set };
command_t syn_facility_addbl = { "ADDBL", N_("Adds a blacklist entry for a faciltiy"), "syn:facility", 2, syn_cmd_facility_addbl };
command_t syn_facility_rmbl = { "RMBL", N_("Removes a blacklist entry from a facility"), "syn:facility", 2, syn_cmd_facility_rmbl };
command_t syn_facility_show = { "SHOW", N_("Displays information about a facility"), "syn:facility", 1, syn_cmd_facility_show };

typedef enum
{
    facility_cloak_undefined,
    facility_cloak_none,
    facility_cloak_random,
    facility_cloak_hex_ident
} facility_cloak_type;

static struct {
    const char *name;
    facility_cloak_type value;
} cloak_type_map[] = {
    { "undefined", facility_cloak_undefined },
    { "none",      facility_cloak_none      },
    { "random",    facility_cloak_random    },
    { "hexip",     facility_cloak_hex_ident },
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

    list_t blacklist;

    time_t throttle_latest;
} facility_t;

typedef struct
{
    char *regex;
    atheme_regex_t *re;
} bl_entry_t;

mowgli_dictionary_t *facilities;

unsigned int block_report_interval = 60;
time_t last_block_report = 0;

BlockHeap *facility_heap, *blacklist_heap;

void free_facility(mowgli_dictionary_elem_t *e, void *v)
{
    facility_t *f = e->data;

    if (f->blockmessage)
        free(f->blockmessage);
    if (f->throttlemessage)
        free(f->throttlemessage);

    node_t *n, *tn;
    LIST_FOREACH_SAFE(n, tn, f->blacklist.head)
    {
        bl_entry_t *bl = n->data;
        free(bl->regex);
        regex_destroy(bl->re);

        BlockHeapFree(blacklist_heap, bl);

        node_del(n, &f->blacklist);
        node_free(n);
    }

    BlockHeapFree(facility_heap, f);
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
            curr_facility = BlockHeapAlloc(facility_heap);
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

            mowgli_dictionary_add(facilities, curr_facility->hostpart, curr_facility);
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

            bl_entry_t *bl = BlockHeapAlloc(blacklist_heap);
            bl->regex = sstrdup(regex);
            bl->re = regex_create(bl->regex, AREGEX_ICASE | AREGEX_PCRE);
            node_add(bl, node_create(), &curr_facility->blacklist);
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

    mowgli_dictionary_iteration_state_t state;
    facility_t *f;
    MOWGLI_DICTIONARY_FOREACH(f, &state, facilities)
    {
        fprintf(db, "F %s %s %d %d %d\n", f->hostpart, string_from_cloak_type(f->cloaking),
                f->blocked, f->throttle[0], f->throttle[1]);
        if (f->blockmessage)
            fprintf(db, "BM %s\n", f->blockmessage);
        if (f->throttlemessage)
            fprintf(db, "TM %s\n", f->throttlemessage);
        node_t *n;
        LIST_FOREACH(n, f->blacklist.head)
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

void _modinit(module_t *m)
{
    use_syn_main_symbols(m);
    use_syn_util_symbols(m);
    use_syn_kline_symbols(m);

    hook_add_event("user_add");
    hook_add_hook("user_add", facility_newuser);

    command_add(&syn_facility, syn_cmdtree);

    command_add(&syn_facility_list, &syn_facility_cmds);
    command_add(&syn_facility_add, &syn_facility_cmds);
    command_add(&syn_facility_del, &syn_facility_cmds);
    command_add(&syn_facility_set, &syn_facility_cmds);
    command_add(&syn_facility_addbl, &syn_facility_cmds);
    command_add(&syn_facility_rmbl, &syn_facility_cmds);
    command_add(&syn_facility_show, &syn_facility_cmds);

    help_addentry(syn_helptree, "FACILITY", "help/syn/facility", NULL);
    help_addentry(syn_helptree, "FACILITY ADD", "help/syn/facility_add", NULL);
    help_addentry(syn_helptree, "FACILITY DEL", "help/syn/facility_del", NULL);
    help_addentry(syn_helptree, "FACILITY SET", "help/syn/facility_set", NULL);
    help_addentry(syn_helptree, "FACILITY ADDBL", "help/syn/facility_addbl", NULL);
    help_addentry(syn_helptree, "FACILITY RMBL", "help/syn/facility_rmbl", NULL);
    help_addentry(syn_helptree, "FACILITY LIST", "help/syn/facility_list", NULL);

    facility_heap = BlockHeapCreate(sizeof(facility_t), HEAP_USER);
    blacklist_heap = BlockHeapCreate(sizeof(bl_entry_t), HEAP_USER);
    facilities = mowgli_dictionary_create(strcasecmp);

    add_uint_conf_item("FACILITY_REPORT_RATE", syn_conftable, &block_report_interval, 0, 3600);

    load_facilities();
}

void _moddeinit()
{
    save_facilities();

    del_conf_item("FACILITY_REPORT_RATE", syn_conftable);

    mowgli_dictionary_destroy(facilities, free_facility, NULL);
    BlockHeapDestroy(facility_heap);
    BlockHeapDestroy(blacklist_heap);

    help_delentry(syn_helptree, "FACILITY");
    help_delentry(syn_helptree, "FACILITY ADD");
    help_delentry(syn_helptree, "FACILITY DEL");
    help_delentry(syn_helptree, "FACILITY SET");
    help_delentry(syn_helptree, "FACILITY ADDBL");
    help_delentry(syn_helptree, "FACILITY RMBL");
    help_delentry(syn_helptree, "FACILITY LIST");

    command_delete(&syn_facility, syn_cmdtree);

    hook_del_hook("user_add", facility_newuser);
}

void facility_newuser(void *v)
{
    user_t *u = v;
    facility_t *f;
    mowgli_dictionary_iteration_state_t state;

    int blocked = 0, throttled = 0, blacklisted = 0;
    char *blockmessage = NULL, *throttlemessage = NULL;
    facility_cloak_type cloak = facility_cloak_none;
    facility_t *blocking_facility = NULL, *throttling_facility = NULL;
    char *blocking_regex = NULL;

    MOWGLI_DICTIONARY_FOREACH(f, &state, facilities)
    {
        if (0 != strncasecmp(u->host, f->hostpart, strlen(f->hostpart)))
            continue;

        syn_debug(2, "User %s matches facility %s", u->nick, f->hostpart);

        if (f->blocked > 0)
        {
            blocked = 1;
            blocking_facility = f;
        }
        if (f->blocked < 0)
            blocked = 0;

        if (f->blockmessage)
            blockmessage = f->blockmessage;

        if (f->throttle[0] > 0)
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

        node_t *n;
        LIST_FOREACH(n, f->blacklist.head)
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
    }

    char *slash = strchr(u->vhost, '/');
    if (slash != NULL && 0 != strncmp(u->vhost, "unaffiliated", slash - u->vhost))
        return;

    strncpy(u->vhost, u->host, HOSTLEN);
    switch (cloak)
    {
        case facility_cloak_none:
        case facility_cloak_undefined:
            break;

        case facility_cloak_hex_ident:
            {
                char *ipstart = strstr(u->vhost, "session");
                if (ipstart == NULL)
                {
                    syn_debug(2, "Hex IP cloaking used for %s, but I couldn't find a session marker in %s", u->nick, u->vhost);
                    break;
                }
                const char *ident = u->user;
                if (*ident == '~')
                    ++ident;
                const char *ip = decode_hex_ip(ident);

                if (ip)
                {
                    strncpy(ipstart, "ip.", u->vhost + HOSTLEN - ipstart);
                    ipstart += 3;
                    strncpy(ipstart, ip, u->vhost + HOSTLEN - ipstart);
                    sethost_sts(syn->me, u, u->vhost);
                    break;
                }
                // If we couldn't decode an IP, fall through...
                syn_debug(2, "Hex IP cloaking used for %s, but I couldn't decode ident %s", u->nick, ident);
                syn_debug(2, "Falling back to random cloaking...");
            }
        case facility_cloak_random:
            {
                char *randstart = strstr(u->vhost, "session");
                if (randstart == NULL)
                {
                    syn_debug(2, "Random cloaking used for %s, but I couldn't find a session marker in %s", u->nick, u->vhost);
                    break;
                }
                strncpy(randstart, get_random_host_part(), u->vhost + HOSTLEN - randstart);
                sethost_sts(syn->me, u, u->vhost);
                break;
            }
    }
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

    c = command_find(&syn_facility_cmds, cmd);
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
    mowgli_dictionary_iteration_state_t state;
    MOWGLI_DICTIONARY_FOREACH(f, &state, facilities)
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

    facility_t *f = BlockHeapAlloc(facility_heap);
    strncpy(f->hostpart, hostpart, HOSTLEN);
    f->cloaking = cloak;

    mowgli_dictionary_add(facilities, f->hostpart, f);

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

    mowgli_dictionary_elem_t *f = mowgli_dictionary_find(facilities, parv[0]);

    if (f == NULL)
    {
        command_fail(si, fault_badparams, "No such facility %s was found.", parv[0]);
        return;
    }

    free_facility(f, NULL);
    mowgli_dictionary_delete(facilities, parv[0]);

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

    facility_t *f = mowgli_dictionary_retrieve(facilities, parv[0]);
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
        return;
    }

    command_fail(si, fault_badparams, "Unknown setting name");

    save_facilities();
}



void syn_cmd_facility_addbl(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 2)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "FACILITY ADDBL");
        command_fail(si, fault_needmoreparams, "Syntax: FACILITY ADDBL <hostpart> <regex>");
        return;
    }

    facility_t *f = mowgli_dictionary_retrieve(facilities, parv[0]);
    if (f== NULL)
    {
        command_fail(si, fault_badparams, "No such facility %s", parv[0]);
        return;
    }

    bl_entry_t *bl = BlockHeapAlloc(blacklist_heap);
    bl->regex = sstrdup(parv[1]);
    bl->re = regex_create(bl->regex, AREGEX_ICASE | AREGEX_PCRE);

    node_add(bl, node_create(), &f->blacklist);

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

    facility_t *f = mowgli_dictionary_retrieve(facilities, parv[0]);
    if (f== NULL)
    {
        command_fail(si, fault_badparams, "No such facility %s", parv[0]);
        return;
    }

    node_t *n, *tn;
    LIST_FOREACH_SAFE(n, tn, f->blacklist.head)
    {
        bl_entry_t *bl = n->data;
        if (0 != strcmp(parv[1], bl->regex))
            continue;

        free(bl->regex);
        regex_destroy(bl->re);

        BlockHeapFree(blacklist_heap, bl);

        node_del(n, &f->blacklist);
        node_free(n);

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

    facility_t *f = mowgli_dictionary_retrieve(facilities, parv[0]);
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
    node_t *n;
    LIST_FOREACH(n, f->blacklist.head)
    {
        bl_entry_t *bl = n->data;
        command_success_nodata(si, "[%d] %s", ++count, bl->regex);
    }
    command_success_nodata(si, "%d blacklist entries for %s", count, f->hostpart);
}
