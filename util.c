#include "atheme.h"
#include "syn.h"

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

const char *_get_random_host_part()
{
    static char buf[19];

    strcpy(buf, "x-");

    for (int i=2; i < 18; ++i)
    {
        buf[i] = 'a' + rand() % 26;
    }
    buf[18] = 0;
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

DECLARE_MODULE_V1
(
        "syn/util", false, NULL, NULL,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);
