#include "atheme.h"

const char *decode_hex_ip(const char *hex)
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

const char *get_random_host_part()
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

time_t syn_parse_duration(const char *s)
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

const char *syn_format_expiry(time_t t)
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
