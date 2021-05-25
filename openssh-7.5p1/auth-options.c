/* $OpenBSD: auth-options.c,v 1.72 2016/11/30 02:57:40 djm Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#include "includes.h"

#include <sys/types.h>

#include <netdb.h>
#include <pwd.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include "openbsd-compat/sys-queue.h"

#include "key.h"	/* XXX for typedef */
#include "buffer.h"	/* XXX for typedef */
#include "xmalloc.h"
#include "match.h"
#include "ssherr.h"
#include "log.h"
#include "canohost.h"
#include "packet.h"
#include "sshbuf.h"
#include "misc.h"
#include "channels.h"
#include "servconf.h"
#include "sshkey.h"
#include "auth-options.h"
#include "hostfile.h"
#include "auth.h"

/* Flags set authorized_keys flags */
int no_port_forwarding_flag = 0;
int no_agent_forwarding_flag = 0;
int no_x11_forwarding_flag = 0;
int no_pty_flag = 0;
int no_user_rc = 0;
int key_is_cert_authority = 0;

/* "command=" option. */
char *forced_command = NULL;

/* "environment=" options. */
struct envstring *custom_environment = NULL;

/* "tunnel=" option. */
int forced_tun_device = -1;

/* "principals=" option. */
char *authorized_principals = NULL;

extern ServerOptions options;

void
auth_clear_options(void)
{
	no_agent_forwarding_flag = 0;
	no_port_forwarding_flag = 0;
	no_pty_flag = 0;
	no_x11_forwarding_flag = 0;
	no_user_rc = 0;
	key_is_cert_authority = 0;
	while (custom_environment) {
		struct envstring *ce = custom_environment;
		custom_environment = ce->next;
		free(ce->s);
		free(ce);
	}
	free(forced_command);
	forced_command = NULL;
	free(authorized_principals);
	authorized_principals = NULL;
	forced_tun_device = -1;
	channel_clear_permitted_opens();
}

/*
 * Match flag 'opt' in *optsp, and if allow_negate is set then also match
 * 'no-opt'. Returns -1 if option not matched, 1 if option matches or 0
 * if negated option matches. 
 * If the option or negated option matches, then *optsp is updated to
 * point to the first character after the option and, if 'msg' is not NULL
 * then a message based on it added via auth_debug_add().
 */
static int
match_flag(const char *opt, int allow_negate, char **optsp, const char *msg)
{
	size_t opt_len = strlen(opt);
	char *opts = *optsp;
	int negate = 0;

	if (allow_negate && strncasecmp(opts, "no-", 3) == 0) {
		opts += 3;
		negate = 1;
	}
	if (strncasecmp(opts, opt, opt_len) == 0) {
		*optsp = opts + opt_len;
		if (msg != NULL) {
			auth_debug_add("%s %s.", msg,
			    negate ? "disabled" : "enabled");
		}
		return negate ? 0 : 1;
	}
	return -1;
}

/*
 * return 1 if access is granted, 0 if not.
 * side effect: sets key option flags
 */
int
auth_parse_options(struct passwd *pw, char *opts, char *file, u_long linenum)
{
	struct ssh *ssh = active_state;		/* XXX */
	const char *cp;
	int i, r;

	/* reset options */
	auth_clear_options();

	if (!opts)
		return 1;

	while (*opts && *opts != ' ' && *opts != '\t') {
		if ((r = match_flag("cert-authority", 0, &opts, NULL)) != -1) {
			key_is_cert_authority = r;
			goto next_option;
		}
		if ((r = match_flag("restrict", 0, &opts, NULL)) != -1) {
			auth_debug_add("Key is restricted.");
			no_port_forwarding_flag = 1;
			no_agent_forwarding_flag = 1;
			no_x11_forwarding_flag = 1;
			no_pty_flag = 1;
			no_user_rc = 1;
			goto next_option;
		}
		if ((r = match_flag("port-forwarding", 1, &opts,
		    "Port forwarding")) != -1) {
			no_port_forwarding_flag = r != 1;
			goto next_option;
		}
		if ((r = match_flag("agent-forwarding", 1, &opts,
		    "Agent forwarding")) != -1) {
			no_agent_forwarding_flag = r != 1;
			goto next_option;
		}
		if ((r = match_flag("x11-forwarding", 1, &opts,
		    "X11 forwarding")) != -1) {
			no_x11_forwarding_flag = r != 1;
			goto next_option;
		}
		if ((r = match_flag("pty", 1, &opts,
		    "PTY allocation")) != -1) {
			no_pty_flag = r != 1;
			goto next_option;
		}
		if ((r = match_flag("user-rc", 1, &opts,
		    "User rc execution")) != -1) {
			no_user_rc = r != 1;
			goto next_option;
		}
		cp = "command=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			opts += strlen(cp);
			free(forced_command);
			forced_command = xmalloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					forced_command[i++] = '"';
					continue;
				}
				forced_command[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(forced_command);
				forced_command = NULL;
				goto bad_option;
			}
			forced_command[i] = '\0';
			auth_debug_add("Forced command.");
			opts++;
			goto next_option;
		}
		cp = "principals=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			opts += strlen(cp);
			free(authorized_principals);
			authorized_principals = xmalloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					authorized_principals[i++] = '"';
					continue;
				}
				authorized_principals[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(authorized_principals);
				authorized_principals = NULL;
				goto bad_option;
			}
			authorized_principals[i] = '\0';
			auth_debug_add("principals: %.900s",
			    authorized_principals);
			opts++;
			goto next_option;
		}
		cp = "environment=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			char *s;
			struct envstring *new_envstring;

			opts += strlen(cp);
			s = xmalloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					s[i++] = '"';
					continue;
				}
				s[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(s);
				goto bad_option;
			}
			s[i] = '\0';
			opts++;
			if (options.permit_user_env) {
				auth_debug_add("Adding to environment: "
				    "%.900s", s);
				debug("Adding to environment: %.900s", s);
				new_envstring = xcalloc(1,
				    sizeof(*new_envstring));
				new_envstring->s = s;
				new_envstring->next = custom_environment;
				custom_environment = new_envstring;
				s = NULL;
			}
			free(s);
			goto next_option;
		}
		cp = "from=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			const char *remote_ip = ssh_remote_ipaddr(ssh);
			const char *remote_host = auth_get_canonical_hostname(
			    ssh, options.use_dns);
			char *patterns = xmalloc(strlen(opts) + 1);

			opts += strlen(cp);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					patterns[i++] = '"';
					continue;
				}
				patterns[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(patterns);
				goto bad_option;
			}
			patterns[i] = '\0';
			opts++;
			switch (match_host_and_ip(remote_host, remote_ip,
			    patterns)) {
			case 1:
				free(patterns);
				/* Host name matches. */
				goto next_option;
			case -1:
				debug("%.100s, line %lu: invalid criteria",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: "
				    "invalid criteria", file, linenum);
				/* FALLTHROUGH */
			case 0:
				free(patterns);
				logit("Authentication tried for %.100s with "
				    "correct key but not from a permitted "
				    "host (host=%.200s, ip=%.200s).",
				    pw->pw_name, remote_host, remote_ip);
				auth_debug_add("Your host '%.200s' is not "
				    "permitted to use this key for login.",
				    remote_host);
				break;
			}
			/* deny access */
			return 0;
		}
		cp = "permitopen=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			char *host, *p;
			int port;
			char *patterns = xmalloc(strlen(opts) + 1);

			opts += strlen(cp);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				if (*opts == '\\' && opts[1] == '"') {
					opts += 2;
					patterns[i++] = '"';
					continue;
				}
				patterns[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing "
				    "end quote", file, linenum);
				free(patterns);
				goto bad_option;
			}
			patterns[i] = '\0';
			opts++;
			p = patterns;
			/* XXX - add streamlocal support */
			host = hpdelim(&p);
			if (host == NULL || strlen(host) >= NI_MAXHOST) {
				debug("%.100s, line %lu: Bad permitopen "
				    "specification <%.100s>", file, linenum,
				    patterns);
				auth_debug_add("%.100s, line %lu: "
				    "Bad permitopen specification", file,
				    linenum);
				free(patterns);
				goto bad_option;
			}
			host = cleanhostname(host);
			if (p == NULL || (port = permitopen_port(p)) < 0) {
				debug("%.100s, line %lu: Bad permitopen port "
				    "<%.100s>", file, linenum, p ? p : "");
				auth_debug_add("%.100s, line %lu: "
				    "Bad permitopen port", file, linenum);
				free(patterns);
				goto bad_option;
			}
			if ((options.allow_tcp_forwarding & FORWARD_LOCAL) != 0)
				channel_add_permitted_opens(host, port);
			free(patterns);
			goto next_option;
		}
		cp = "tunnel=\"";
		if (strncasecmp(opts, cp, strlen(cp)) == 0) {
			char *tun = NULL;
			opts += strlen(cp);
			tun = xmalloc(strlen(opts) + 1);
			i = 0;
			while (*opts) {
				if (*opts == '"')
					break;
				tun[i++] = *opts++;
			}
			if (!*opts) {
				debug("%.100s, line %lu: missing end quote",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: missing end quote",
				    file, linenum);
				free(tun);
				forced_tun_device = -1;
				goto bad_option;
			}
			tun[i] = '\0';
			forced_tun_device = a2tun(tun, NULL);
			free(tun);
			if (forced_tun_device == SSH_TUNID_ERR) {
				debug("%.100s, line %lu: invalid tun device",
				    file, linenum);
				auth_debug_add("%.100s, line %lu: invalid tun device",
				    file, linenum);
				forced_tun_device = -1;
				goto bad_option;
			}
			auth_debug_add("Forced tun device: %d", forced_tun_device);
			opts++;
			goto next_option;
		}
next_option:
		/*
		 * Skip the comma, and move to the next option
		 * (or break out if there are no more).
		 */
		if (!*opts)
			fatal("Bugs in auth-options.c option processing.");
		if (*opts == ' ' || *opts == '\t')
			break;		/* End of options. */
		if (*opts != ',')
			goto bad_option;
		opts++;
		/* Process the next option. */
	}

	/* grant access */
	return 1;

bad_option:
	logit("Bad options in %.100s file, line %lu: %.50s",
	    file, linenum, opts);
	auth_debug_add("Bad options in %.100s file, line %lu: %.50s",
	    file, linenum, opts);

	/* deny access */
	return 0;
}

#define OPTIONS_CRITICAL	1
#define OPTIONS_EXTENSIONS	2
static int
parse_option_list(struct sshbuf *oblob, struct passwd *pw,
    u_int which, int crit,
    int *cert_no_port_forwarding_flag,
    int *cert_no_agent_forwarding_flag,
    int *cert_no_x11_forwarding_flag,
    int *cert_no_pty_flag,
    int *cert_no_user_rc,
    char **cert_forced_command,
    int *cert_source_address_done)
{
	struct ssh *ssh = active_state;		/* XXX */
	char *command, *allowed;
	const char *remote_ip;
	char *name = NULL;
	struct sshbuf *c = NULL, *data = NULL;
	int r, ret = -1, result, found;

	if ((c = sshbuf_fromb(oblob)) == NULL) {
		error("%s: sshbuf_fromb failed", __func__);
		goto out;
	}

	while (sshbuf_len(c) > 0) {
		sshbuf_free(data);
		data = NULL;
		if ((r = sshbuf_get_cstring(c, &name, NULL)) != 0 ||
		    (r = sshbuf_froms(c, &data)) != 0) {
			error("Unable to parse certificate options: %s",
			    ssh_err(r));
			goto out;
		}
		debug3("found certificate option \"%.100s\" len %zu",
		    name, sshbuf_len(data));
		found = 0;
		if ((which & OPTIONS_EXTENSIONS) != 0) {
			if (strcmp(name, "permit-X11-forwarding") == 0) {
				*cert_no_x11_forwarding_flag = 0;
				found = 1;
			} else if (strcmp(name,
			    "permit-agent-forwarding") == 0) {
				*cert_no_agent_forwarding_flag = 0;
				found = 1;
			} else if (strcmp(name,
			    "permit-port-forwarding") == 0) {
				*cert_no_port_forwarding_flag = 0;
				found = 1;
			} else if (strcmp(name, "permit-pty") == 0) {
				*cert_no_pty_flag = 0;
				found = 1;
			} else if (strcmp(name, "permit-user-rc") == 0) {
				*cert_no_user_rc = 0;
				found = 1;
			}
		}
		if (!found && (which & OPTIONS_CRITICAL) != 0) {
			if (strcmp(name, "force-command") == 0) {
				if ((r = sshbuf_get_cstring(data, &command,
				    NULL)) != 0) {
					error("Unable to parse \"%s\" "
					    "section: %s", name, ssh_err(r));
					goto out;
				}
				if (*cert_forced_command != NULL) {
					error("Certificate has multiple "
					    "force-command options");
					free(command);
					goto out;
				}
				*cert_forced_command = command;
				found = 1;
			}
			if (strcmp(name, "source-address") == 0) {
				if ((r = sshbuf_get_cstring(data, &allowed,
				    NULL)) != 0) {
					error("Unable to parse \"%s\" "
					    "section: %s", name, ssh_err(r));
					goto out;
				}
				if ((*cert_source_address_done)++) {
					error("Certificate has multiple "
					    "source-address options");
					free(allowed);
					goto out;
				}
				remote_ip = ssh_remote_ipaddr(ssh);
				result = addr_match_cidr_list(remote_ip,
				    allowed);
				free(allowed);
				switch (result) {
				case 1:
					/* accepted */
					break;
				case 0:
					/* no match */
					logit("Authentication tried for %.100s "
					    "with valid certificate but not "
					    "from a permitted host "
					    "(ip=%.200s).", pw->pw_name,
					    remote_ip);
					auth_debug_add("Your address '%.200s' "
					    "is not permitted to use this "
					    "certificate for login.",
					    remote_ip);
					goto out;
				case -1:
				default:
					error("Certificate source-address "
					    "contents invalid");
					goto out;
				}
				found = 1;
			}
		}

		if (!found) {
			if (crit) {
				error("Certificate critical option \"%s\" "
				    "is not supported", name);
				goto out;
			} else {
				logit("Certificate extension \"%s\" "
				    "is not supported", name);
			}
		} else if (sshbuf_len(data) != 0) {
			error("Certificate option \"%s\" corrupt "
			    "(extra data)", name);
			goto out;
		}
		free(name);
		name = NULL;
	}
	/* successfully parsed all options */
	ret = 0;

 out:
	if (ret != 0 &&
	    cert_forced_command != NULL &&
	    *cert_forced_command != NULL) {
		free(*cert_forced_command);
		*cert_forced_command = NULL;
	}
	free(name);
	sshbuf_free(data);
	sshbuf_free(c);
	return ret;
}

/*
 * Set options from critical certificate options. These supersede user key
 * options so this must be called after auth_parse_options().
 */
int
auth_cert_options(struct sshkey *k, struct passwd *pw, const char **reason)
{
	int cert_no_port_forwarding_flag = 1;
	int cert_no_agent_forwarding_flag = 1;
	int cert_no_x11_forwarding_flag = 1;
	int cert_no_pty_flag = 1;
	int cert_no_user_rc = 1;
	char *cert_forced_command = NULL;
	int cert_source_address_done = 0;

	*reason = "invalid certificate options";

	/* Separate options and extensions for v01 certs */
	if (parse_option_list(k->cert->critical, pw,
	    OPTIONS_CRITICAL, 1, NULL, NULL, NULL, NULL, NULL,
	    &cert_forced_command,
	    &cert_source_address_done) == -1)
		return -1;
	if (parse_option_list(k->cert->extensions, pw,
	    OPTIONS_EXTENSIONS, 0,
	    &cert_no_port_forwarding_flag,
	    &cert_no_agent_forwarding_flag,
	    &cert_no_x11_forwarding_flag,
	    &cert_no_pty_flag,
	    &cert_no_user_rc,
	    NULL, NULL) == -1)
		return -1;

	no_port_forwarding_flag |= cert_no_port_forwarding_flag;
	no_agent_forwarding_flag |= cert_no_agent_forwarding_flag;
	no_x11_forwarding_flag |= cert_no_x11_forwarding_flag;
	no_pty_flag |= cert_no_pty_flag;
	no_user_rc |= cert_no_user_rc;
	/*
	 * Only permit both CA and key option forced-command if they match.
	 * Otherwise refuse the certificate.
	 */
	if (cert_forced_command != NULL && forced_command != NULL) {
		if (strcmp(forced_command, cert_forced_command) == 0) {
			free(forced_command);
			forced_command = cert_forced_command;
		} else {
			*reason = "certificate and key options forced command "
			    "do not match";
			free(cert_forced_command);
			return -1;
		}
	} else if (cert_forced_command != NULL)
		forced_command = cert_forced_command;
	/* success */
	*reason = NULL;
	return 0;
}

