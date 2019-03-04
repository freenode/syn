#include "atheme.h"
#include "syn.h"

#define PRF_KEY_LEN 16
#define PRF_KEY_HEX_LEN (PRF_KEY_LEN * 2)
#define PRF_OUT_LEN 16

char *prf_key_hex = NULL;
uint8_t prf_key[PRF_KEY_LEN];
bool prf_ready = false;

const char *_decode_hex_ip(const char *hex)
{
    static char buf[16];
    unsigned int ip = 0;

    buf[0] = '\0';

    if (strlen(hex) != 8)
        return NULL;

    char *endptr;
    ip = strtoul(hex, &endptr, 16);
    if (*endptr)
        return NULL;

    sprintf(buf, "%hhu.%hhu.%hhu.%hhu", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
    return buf;
}

const char *_get_random_host_part(user_t *u)
{
    // UID, user, host, '!', '@', NUL
    static char user_buf[9 + USERLEN + HOSTLEN + 3];
    static char buf[PRF_OUT_LEN + 3];

    strcpy(buf, "x-");
    snprintf(user_buf, sizeof user_buf, "%s!%s@%s", u->uid, u->user, u->host);

    if (!prf_ready)
    {
        syn_debug(2, "PRF key not configured, falling back to random cloaking");
        for (size_t i = 0; i < PRF_OUT_LEN; ++i)
        {
            buf[i + 2] = 'a' + rand() % 26;
        }
    }
    else
    {
        int siphash(const uint8_t *in, const size_t inlen, const uint8_t *k,
                uint8_t *out, const size_t outlen);

        uint8_t out[PRF_OUT_LEN];
        siphash((unsigned char*)user_buf, strlen(user_buf), prf_key, out, PRF_OUT_LEN);

        for (size_t i=0; i < PRF_OUT_LEN; ++i)
        {
            buf[i + 2] = 'a' + out[i] % 26;
        }
    }

    buf[PRF_OUT_LEN + 2] = 0;
    return buf;
}

// Taken from ircd-seven extensions/sasl_usercloak.c, modified for const correctness
static unsigned int fnv_hash_string(const char *str)
{
    unsigned int hash = 0x811c9dc5; // Magic value for 32-bit fnv1 hash initialisation.
    unsigned const char *p = (unsigned const char *)str;
    while (*p)
    {
        hash += (hash<<1) + (hash<<4) + (hash<<7) + (hash<<8) + (hash<<24);
        hash ^= *p++;
    }
    return hash;
}

// Make sure to keep these in agreement.
#define SUFFIX_HASH_LENGTH 8
#define SUFFIX_HASH_FMT "%08ud"
#define SUFFIX_HASH_MODULUS 100000000

const char *_encode_ident_for_host(const char *str)
{
    // ident + /x- + SUFFIX_HASH_LENGTH, and nul terminator
    static char buf[USERLEN + SUFFIX_HASH_LENGTH + 3 + 1];
    bool needhash = false;

    char *dst = buf;
    for (const char *src = str; *src; src++)
    {
        if (str - src > USERLEN)
        {
            slog(LG_ERROR, "encode_ident_for_host(): tried to encode %s which is too long", str);
            return NULL;
        }

        // For now, consider alphanumerics valid, as well as -
        // . is technically possible in ident, but might be confused for cloak formatting
        // Digits are not allowed unless there was another character successfully reproduced
        // since this could otherwise produce output that looks like a CIDR mask,
        // which messes with bans and is generally not done.
        if (IsAlpha(*src) || (IsDigit(*src) && dst != buf) || *src == '-')
            *dst++ = *src;
        else
            needhash = true;
    }

    *dst = '\0';

    if (needhash)
    {
        unsigned int hashval = fnv_hash_string(str);
        hashval %= SUFFIX_HASH_MODULUS;
        snprintf(dst, 3 + SUFFIX_HASH_LENGTH + 1, "/x-" SUFFIX_HASH_FMT, hashval);
    }

    return buf;
}

time_t _syn_parse_duration(const char *s)
{
    time_t duration = atol(s);
    while (isdigit(*s))
        s++;
    switch (*s)
    {
        case 'H':
        case 'h':
            duration *= 60;
            break;
        case 'D':
        case 'd':
            duration *= 1440;
            break;
        case 'W':
        case 'w':
            duration *= 10080;
            break;
    }
    return duration;
}

const char *_syn_format_expiry(time_t t)
{
    static char expirybuf[BUFSIZE];
    if (t > 0)
    {
        strftime(expirybuf, BUFSIZE, "%d/%m/%Y %H:%M:%S", gmtime(&t));
    }
    else
    {
        strcpy(expirybuf, "never");
    }

    return expirybuf;
}

static void syn_util_config_ready(void *unused)
{
    if (prf_key_hex == NULL)
    {
        slog(LG_ERROR, "syn/util: could not find 'prf_key' configuration entry");
        prf_ready = false;
        return;
    }

    if (strlen(prf_key_hex) != PRF_KEY_HEX_LEN)
    {
        slog(LG_ERROR, "syn/util: prf_key must be exactly %d hex digits", PRF_KEY_HEX_LEN);
        prf_ready = false;
        return;
    }

    // This could be done in a single big sscanf, but let's not do that
    for (size_t i = 0; i < PRF_KEY_LEN; i++)
    {
        if (sscanf(prf_key_hex + (i * 2), "%2" SCNx8, &prf_key[i]) != 1)
        {
            slog(LG_ERROR, "syn/util: failed to parse prf_key - must be string of hex digits");
            prf_ready = false;
            return;
        }
    }

    prf_ready = true;
}

static void mod_init(module_t *m)
{
    use_syn_main_symbols(m);

    add_dupstr_conf_item("PRF_KEY", &syn->conf_table, 0, &prf_key_hex, NULL);
    hook_add_config_ready(syn_util_config_ready);
}

static void mod_deinit(module_unload_intent_t unused)
{
    del_conf_item("PRF_KEY", &syn->conf_table);
    hook_del_config_ready(syn_util_config_ready);
}

DECLARE_MODULE_V1
(
        "syn/util", false, mod_init, mod_deinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
