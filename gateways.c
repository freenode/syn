/*
 * syn: a utility bot to manage IRC network access
 * Copyright (C) 2009-2016 Stephen Bennett
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */


#include "atheme.h"
#include "uplink.h"

#include "syn.h"

static void check_user(hook_user_nick_t *data, bool isnewuser);
static bool maybe_kline_user_host(user_t *u, const char *hostname);

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

    check_all_users(NULL);
}

static void mod_deinit(module_unload_intent_t intent)
{
    hook_del_user_add(gateway_newuser);
    hook_del_hook("syn_kline_added", check_all_users);
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

    // As above, but for gecos hostnames
    syn_kline_check_data_t d = { gecos, u };
    hook_call_event("syn_kline_check", &d);
    d.ip = p;
    hook_call_event("syn_kline_check", &d);
}

DECLARE_MODULE_V1
(
        "syn/gateways", false, mod_init, mod_deinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
