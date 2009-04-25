#ifndef syn_h
#define syn_h

service_t *syn;
list_t *syn_cmdtree;
list_t *syn_helptree;
list_t *syn_conftable;

void (*syn_report)(char *, ...);
void (*syn_debug)(int, char *, ...);

inline void use_syn_main_symbols(module_t *m)
{
    MODULE_USE_SYMBOL(syn_cmdtree, "syn/main", "syn_cmdtree");
    MODULE_USE_SYMBOL(syn_helptree, "syn/main", "syn_helptree");
    MODULE_USE_SYMBOL(syn_conftable, "syn/main", "syn_conftable");
    MODULE_USE_SYMBOL(syn_report, "syn/main", "syn_report");
    MODULE_USE_SYMBOL(syn_debug, "syn/main", "syn_debug");
    service_t **syn_tmp;
    MODULE_USE_SYMBOL(syn_tmp, "syn/main", "syn");
    syn = *syn_tmp;
}

const char* (*decode_hex_ip)(const char *);
const char* (*get_random_host_part)();

inline void use_syn_util_symbols(module_t *m)
{
    MODULE_USE_SYMBOL(decode_hex_ip, "syn/util", "decode_hex_ip");
    MODULE_USE_SYMBOL(get_random_host_part, "syn/util", "get_random_host_part");
}

kline_t* (*syn_find_kline)(const char *, const char *);
void (*syn_kline)(const char *, int, const char *, ...);
void (*syn_kill)(user_t *, const char *, ...);
void (*syn_kill2)(user_t *, const char *, const char *, ...);
void (*syn_kill_or_kline)(user_t *, int, const char *, ...);

inline void use_syn_kline_symbols(module_t *m)
{
    MODULE_USE_SYMBOL(syn_find_kline, "syn/kline", "_syn_find_kline");
    MODULE_USE_SYMBOL(syn_kline, "syn/kline", "_syn_kline");
    MODULE_USE_SYMBOL(syn_kill, "syn/kline", "_syn_kill");
    MODULE_USE_SYMBOL(syn_kill2, "syn/kline", "_syn_kill2");
    MODULE_USE_SYMBOL(syn_kill_or_kline, "syn/kline", "_syn_kill_or_kline");
}


#endif
