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

#include "syn.h"

static void syn_cmd_help(sourceinfo_t *si, int parc, char *parv[]);

command_t syn_help = { "HELP", N_("Displays contextual help information."), "syn:general", 1, syn_cmd_help };

static void mod_init(module_t *m)
{
    use_syn_main_symbols(m);

    service_named_bind_command("syn", &syn_help);
}

static void mod_deinit(module_unload_intent_t intent)
{
    service_named_unbind_command("syn", &syn_help);
}

/* HELP <command> [params] */
void syn_cmd_help(sourceinfo_t *si, int parc, char *parv[])
{
    char *command = parv[0];

    if (!command)
    {
        command_success_nodata(si, "***** \2%s Help\2 *****", syn->nick);

        command_success_nodata(si, "\2%s\2 is a utility service to control access to the network.", syn->nick);
        command_success_nodata(si, " ");

        command_help(si, syn->commands);

        command_success_nodata(si, _("***** \2End of Help\2 *****"));

        return;
    }

    /* take the command through the hash table */
    help_display(si, syn, command, syn->commands);
}

DECLARE_MODULE_V1
(
        "syn/help", false, mod_init, mod_deinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
