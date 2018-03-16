/*
 * Copyright (c) 2003-2004 E. Will et al.
 * Copyright (c) 2005-2007 Atheme Development Group
 * Rights to this code are documented in doc/LICENSE.
 *
 * This file contains protocol support for ircd-seven.
 *
 */

#include "atheme.h"
#include "uplink.h"
#include "pmodule.h"
#include "protocol/charybdis.h"
#include "protocol/ircd-seven.h"

#include "syn_hooktypes.h"

/* *INDENT-OFF* */

ircd_t SevenSyn = {
        "ircd-seven+syn",		/* IRCd name */
        "$$",                           /* TLD Prefix, used by Global. */
        true,                           /* Whether or not we use IRCNet/TS6 UID */
        false,                          /* Whether or not we use RCOMMAND */
        false,                          /* Whether or not we support channel owners. */
        false,                          /* Whether or not we support channel protection. */
        false,                          /* Whether or not we support halfops. */
	false,				/* Whether or not we use P10 */
	false,				/* Whether or not we use vHosts. */
	CMODE_EXLIMIT | CMODE_PERM | CMODE_IMMUNE, /* Oper-only cmodes */
        0,                              /* Integer flag for owner channel flag. */
        0,                              /* Integer flag for protect channel flag. */
        0,                              /* Integer flag for halfops. */
        "+",                            /* Mode we set for owner. */
        "+",                            /* Mode we set for protect. */
        "+",                            /* Mode we set for halfops. */
	PROTOCOL_CHARYBDIS,		/* Protocol type */
	CMODE_PERM,                     /* Permanent cmodes */
	CMODE_IMMUNE,                   /* Oper-immune cmode */
	"beIq",                         /* Ban-like cmodes */
	'e',                            /* Except mchar */
	'I',                            /* Invex mchar */
	IRCD_CIDR_BANS | IRCD_HOLDNICK | IRCD_TOPIC_NOCOLOUR  /* Flags */
};

static void (*old_m_encap)(sourceinfo_t *si, int parc, char **parv);

static void syn_m_encap(sourceinfo_t *si, int parc, char **parv)
{
	user_t *u;

	if (!irccasecmp(parv[1], "CHGHOST"))
	{
		hook_incoming_host_change_t hdata;
		const char *oldvhost;

		if (parc < 4)
			return;
		u = user_find(parv[2]);
		if (u == NULL)
			return;

		oldvhost = strshare_get(u->vhost);
		strshare_unref(u->vhost);
		u->vhost = strshare_get(parv[3]);

		hdata.si = si;
		hdata.user = u;
		hdata.oldvhost = oldvhost;
		hook_call_event("incoming_host_change", &hdata);

		slog(LG_DEBUG, "m_encap(): chghost %s -> %s", u->nick,
				u->vhost);
	}
	else
	{
		old_m_encap(si, parc, parv);
	}
}

static void syn_m_chghost(sourceinfo_t *si, int parc, char *parv[])
{
	hook_incoming_host_change_t hdata;
	const char *oldvhost;
	user_t *u = user_find(parv[0]);

	if (!u)
		return;

	oldvhost = strshare_get(u->vhost);
	strshare_unref(u->vhost);
	u->vhost = strshare_get(parv[1]);

	hdata.si = si;
	hdata.user = u;
	hdata.oldvhost = oldvhost;
	hook_call_event("incoming_host_change", &hdata);
}

static unsigned int sevensyn_server_login(void)
{
	int ret = 1;

	if (!me.numeric)
	{
		ircd->uses_uid = false;
		ret = sts("PASS %s :TS", curr_uplink->send_pass);
	}
	else if (strlen(me.numeric) == 3 && isdigit(*me.numeric))
	{
		ircd->uses_uid = true;
		ret = sts("PASS %s TS 6 :%s", curr_uplink->send_pass, me.numeric);
	}
	else
	{
		slog(LG_ERROR, "Invalid numeric (SID) %s", me.numeric);
	}
	if (ret == 1)
		return 1;

	me.bursting = true;

	sts("CAPAB :QS EX IE KLN UNKLN ENCAP TB SERVICES EUID EOPMOD MLOCK BAN");
	sts("SERVER %s 1 :%s%s", me.name, me.hidden ? "(H) " : "", me.desc);
	sts("SVINFO %d 3 0 :%lu", ircd->uses_uid ? 6 : 5,
			(unsigned long)CURRTIME);

	return 0;
}

static void mod_init(module_t * m)
{
	MODULE_TRY_REQUEST_DEPENDENCY(m, "protocol/ircd-seven");

	server_login = sevensyn_server_login;

	pcommand_t *old_encap = pcommand_find("ENCAP");
	old_m_encap = old_encap->handler;
	pcommand_delete("ENCAP");
	pcommand_add("ENCAP", syn_m_encap, 2, MSRC_USER | MSRC_SERVER);
	pcommand_delete("CHGHOST");
	pcommand_add("CHGHOST", syn_m_chghost, 2, MSRC_USER | MSRC_SERVER);

	ircd = &SevenSyn;

	m->mflags = MODTYPE_CORE;

	pmodule_loaded = true;
}

DECLARE_MODULE_V1("syn/protocol-ircd-seven", true, mod_init, NULL, PACKAGE_STRING, "Atheme Development Group <http://www.atheme.org>");

/* vim:cinoptions=>s,e0,n0,f0,{0,}0,^0,=s,ps,t0,c3,+s,(2s,us,)20,*30,gs,hs
 * vim:ts=8
 * vim:sw=8
 * vim:noexpandtab
 */
