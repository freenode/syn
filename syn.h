#ifndef syn_h
#define syn_h

service_t *syn;

void (*syn_report)(char *, ...);
void (*syn_report2)(unsigned int, char *, ...);
void (*syn_debug)(int, char *, ...);

static inline void use_syn_main_symbols(module_t *m)
{
    MODULE_TRY_REQUEST_SYMBOL(m, syn_report, "syn/main", "syn_report");
    MODULE_TRY_REQUEST_SYMBOL(m, syn_report2, "syn/main", "syn_report2");
    MODULE_TRY_REQUEST_SYMBOL(m, syn_debug, "syn/main", "syn_debug");
    service_t **syn_tmp;
    MODULE_TRY_REQUEST_SYMBOL(m, syn_tmp, "syn/main", "syn");
    syn = *syn_tmp;
}

const char* (*decode_hex_ip)(const char *);
const char* (*get_random_host_part)();
const char* (*encode_ident_for_host)(const char *);
time_t (*syn_parse_duration)(const char *);
const char* (*syn_format_expiry)(time_t);

static inline void use_syn_util_symbols(module_t *m)
{
    MODULE_TRY_REQUEST_SYMBOL(m, decode_hex_ip, "syn/util", "_decode_hex_ip");
    MODULE_TRY_REQUEST_SYMBOL(m, get_random_host_part, "syn/util", "_get_random_host_part");
    MODULE_TRY_REQUEST_SYMBOL(m, encode_ident_for_host, "syn/util", "_encode_ident_for_host");
    MODULE_TRY_REQUEST_SYMBOL(m, syn_parse_duration, "syn/util", "_syn_parse_duration");
    MODULE_TRY_REQUEST_SYMBOL(m, syn_format_expiry, "syn/util", "_syn_format_expiry");
}

kline_t* (*syn_find_kline)(const char *, const char *);
void (*syn_kline)(const char *, int, const char *, ...);
void (*syn_kill)(user_t *, const char *, ...);
void (*syn_kill2)(user_t *, const char *, const char *, ...);
void (*syn_kill_or_kline)(user_t *, int, const char *, ...);

static inline void use_syn_kline_symbols(module_t *m)
{
    MODULE_TRY_REQUEST_SYMBOL(m, syn_find_kline, "syn/kline", "_syn_find_kline");
    MODULE_TRY_REQUEST_SYMBOL(m, syn_kline, "syn/kline", "_syn_kline");
    MODULE_TRY_REQUEST_SYMBOL(m, syn_kill, "syn/kline", "_syn_kill");
    MODULE_TRY_REQUEST_SYMBOL(m, syn_kill2, "syn/kline", "_syn_kill2");
    MODULE_TRY_REQUEST_SYMBOL(m, syn_kill_or_kline, "syn/kline", "_syn_kill_or_kline");
}

typedef struct
{
    const char *ip;
    user_t *u;
    int added;
} syn_kline_check_data_t;

// This in user_t.flags means the user connected through a facility of some sort,
// so our gateway-cloak-enforcement needs to take effect.
#define SYN_UF_FACILITY_USER    0x80000000
#define SYN_UF_NO_GATEWAY_IP    0x40000000

#include "syn_hooktypes.h"

#endif
