#include "atheme.h"

#include "syn.h"

static void syn_ratecheck(hook_channel_joinpart_t *data);

static void syn_cmd_setrate(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_showrate(sourceinfo_t *si, int parc, char **parv);

command_t syn_setrate = { "SETRATE", N_("Sets join-rate monitoring thresholds"), "syn:general", 3, syn_cmd_setrate };
command_t syn_showrate = { "SHOWRATE", N_("Displays join-rate monitoring thresholds"), "syn:general", 1, syn_cmd_showrate };

int default_rate;
int default_burst;
int warn_time;

typedef struct
{
    char chname[CHANNELLEN];

    bool use_custom;
    int rate[2];

    time_t curr_rate_time;

    time_t last_warn_time;
} channelentry;

mowgli_patricia_t *channellist;
mowgli_heap_t *channelheap;
static void free_channelentry(const char *, void *data, void *);

void load_rate_settings()
{
    FILE *f = fopen(DATADIR "/rates.db", "r");
    if (!f)
    {
        slog(LG_DEBUG, "Couldn't open rates.db for reading: %s", strerror(errno));
        return;
    }

    char line[BUFSIZE];
    while (fgets(line, BUFSIZE, f))
    {
        char *chname = strtok(line, " ");

        if (0 == strcmp(chname, "default"))
        {
            char *srate = strtok(NULL, " ");
            char *sburst = strtok(NULL, " ");
            if (!srate || !sburst)
                continue;

            default_rate = atoi(srate);
            default_burst = atoi(sburst);

            continue;
        }

        char *srate = strtok(NULL, " ");
        char *sburst = strtok(NULL, " ");
        if (!srate || !sburst)
            continue;

        int rate = atoi(srate), burst = atoi(sburst);

        channelentry *ce = mowgli_patricia_retrieve(channellist, chname);
        if (!ce)
        {
            ce = mowgli_heap_alloc(channelheap);
            strncpy(ce->chname, chname, CHANNELLEN);
            ce->use_custom = true;
            mowgli_patricia_add(channellist, chname, ce);
        }
        ce->rate[0] = rate;
        ce->rate[1] = burst;
    }

    fclose(f);
}

void save_rate_settings()
{
    FILE *f = fopen(DATADIR "/rates.db", "w");
    if (!f)
    {
        slog(LG_ERROR, "Couldn't open rates.db for writing: %s", strerror(errno));
        return;
    }
    fprintf(f, "default %d %d\n", default_rate, default_burst);

    channelentry *ce;
    mowgli_patricia_iteration_state_t state;
    MOWGLI_PATRICIA_FOREACH(ce, &state, channellist)
    {
        fprintf(f, "%s %d %d\n", ce->chname, ce->rate[0], ce->rate[1]);
    }
    fclose(f);
}

static void mod_init(module_t *m)
{
    use_syn_main_symbols(m);

    service_named_bind_command("syn", &syn_setrate);
    service_named_bind_command("syn", &syn_showrate);

    hook_add_event("channel_join");
    hook_add_channel_join(syn_ratecheck);

    channellist = mowgli_patricia_create(noopcanon);
    channelheap = mowgli_heap_create(sizeof(channelentry), 512, BH_NOW);

    default_rate = 5;
    default_burst = 5;
    warn_time = 30;

    load_rate_settings();
}

static void mod_deinit(module_unload_intent_t intent)
{
    save_rate_settings();

    mowgli_patricia_destroy(channellist, free_channelentry, NULL);

    service_named_unbind_command("syn", &syn_setrate);
    service_named_unbind_command("syn", &syn_showrate);

    hook_del_channel_join(syn_ratecheck);
}

static void free_channelentry(const char *key, void *data, void *privdata)
{
    mowgli_heap_free(channelheap, data);
}

static void syn_ratecheck(hook_channel_joinpart_t *data)
{
    chanuser_t *cu = data->cu;

    // Don't warn about burst joins.
    if (me.bursting)
        return;

    channelentry *ce = mowgli_patricia_retrieve(channellist, cu->chan->name);
    if (!ce)
    {
        ce = mowgli_heap_alloc(channelheap);
        strncpy(ce->chname, cu->chan->name, CHANNELLEN);
        mowgli_patricia_add(channellist, cu->chan->name, ce);
    }

    int rate, burst;
    if (ce->use_custom)
    {
        rate = ce->rate[0];
        burst = ce->rate[1];
    }
    else
    {
        rate = default_rate;
        burst = default_burst;
    }

    if (ce->curr_rate_time < CURRTIME)
        ce->curr_rate_time = CURRTIME;

    ce->curr_rate_time += rate;
    if (ce->curr_rate_time > (rate * burst) + CURRTIME &&
        ce->last_warn_time + warn_time < CURRTIME)
    {
        ce->last_warn_time = CURRTIME;
        syn_report("Join rate in %s exceeds warning threshold(%d/%d)", ce->chname, rate, burst);
    }
}

static void syn_cmd_showrate(sourceinfo_t *si, int parc, char **parv)
{
    if (parc == 0)
    {
        command_success_nodata(si, "Global warning threshold is %d seconds, %d burst", default_rate, default_burst);
        return;
    }

    channelentry *ce = mowgli_patricia_retrieve(channellist, parv[0]);

    if (!ce || !ce->use_custom)
    {
        command_success_nodata(si, "No custom warning threshold is set for %s", parv[0]);
        return;
    }

    command_success_nodata(si, "Warning threshold for %s is %d seconds, %d burst", ce->chname, ce->rate[0], ce->rate[1]);
}


static void syn_cmd_setrate(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 2)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "SETRATE");
        command_fail(si, fault_needmoreparams, _("Syntax: SETRATE [#channel] default|(<rate> <burst>)"));
        return;
    }

    if (parv[0][0] != '#')
    {
        int r, b;
        r = atoi(parv[0]);
        b = atoi(parv[1]);

        if (r * b == 0)
        {
            command_fail(si, fault_badparams, STR_INVALID_PARAMS, "SETRATE");
            command_fail(si, fault_needmoreparams, _("Syntax: SETRATE [#channel] default|(<rate> <burst>)"));
            return;
        }

        default_rate = r;
        default_burst = b;

        syn_report("\002SETRATE\002 default->%d/%d by %s", default_rate, default_burst, get_oper_name(si));
        command_success_nodata(si, "Warning threshold set to %d seconds, with a burst of %d", default_rate, default_burst);
        save_rate_settings();
        return;
    }

    channelentry *ce = mowgli_patricia_retrieve(channellist, parv[0]);

    if (0 == strcasecmp(parv[1], "default"))
    {
        if (!ce || !ce->use_custom)
        {
            command_fail(si, fault_nochange, "No custom rate settings were defined for %s", parv[0]);
            return;
        }
        ce->use_custom = false;
        syn_report("\002SETRATE\002 %s->default by %s", parv[0], get_oper_name(si));
        command_success_nodata(si, "Custom rate settings have been disabled for %s", parv[0]);
        save_rate_settings();
        return;
    }

    if (parc < 3)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "SETRATE");
        command_fail(si, fault_needmoreparams, _("Syntax: SETRATE [#channel] default|(<rate> <burst>)"));
        return;
    }

    if (!ce)
    {
        ce = mowgli_heap_alloc(channelheap);
        strncpy(ce->chname, parv[0], CHANNELLEN);
        mowgli_patricia_add(channellist, parv[0], ce);
    }

    int r, b;
    r = atoi(parv[1]);
    b = atoi(parv[2]);

    if (r * b == 0)
    {
        command_fail(si, fault_badparams, STR_INVALID_PARAMS, "SETRATE");
        command_fail(si, fault_needmoreparams, _("Syntax: SETRATE [#channel] default|(<rate> <burst>)"));
        return;
    }

    ce->use_custom = true;
    ce->rate[0] = r;
    ce->rate[1] = b;
    ce->curr_rate_time = 0;

    syn_report("\002SETRATE\002 %s->%d/%d by %s", parv[0], r, b, get_oper_name(si));
    command_success_nodata(si, "Warning threshold for %s set to %d seconds, with a burst of %d", parv[0], r, b);
    save_rate_settings();
}

DECLARE_MODULE_V1
(
        "syn/joinrate", false, mod_init, mod_deinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
