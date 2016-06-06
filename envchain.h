#ifndef ENVCHAIN_H
#define ENVCHAIN_H

extern const char *envchain_name;

typedef void (*envchain_search_callback)(const char *key, const char *value,
                                         void *context);
typedef void (*envchain_namespace_search_callback)(const char *name,
                                                   void *context);

typedef struct {
  const char *target;
  int show_value;
} envchain_list_context;

int envchain_search_namespaces(envchain_namespace_search_callback callback,
                               void *data);
int envchain_search_values(const char *name, envchain_search_callback callback,
                           void *data);
void envchain_save_value(const char *name, const char *key, char *value,
                         int require_passphrase);

#endif
