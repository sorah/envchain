#include "envchain.h"
#include <libsecret/secret.h>
#include <stdio.h>

static const SecretSchema *envchain_get_schema(void) {
  static const SecretSchema the_schema = {
      .name = "envchain.EnvironmentVariable",
      .flags = SECRET_SCHEMA_NONE,
      .attributes =
          {
              {.name = "name", .type = SECRET_SCHEMA_ATTRIBUTE_STRING},
              {.name = "key", .type = SECRET_SCHEMA_ATTRIBUTE_STRING},
              {NULL, 0},
          },
  };
  return &the_schema;
}

static GList *search_unlocked_collection(const char *name, GError **error) {
  SecretService *service =
      secret_service_get_sync(SECRET_SERVICE_LOAD_COLLECTIONS, NULL, error);
  if (*error != NULL) {
    return NULL;
  }

  SecretCollection *collection = secret_collection_for_alias_sync(
      service, SECRET_COLLECTION_DEFAULT, SECRET_COLLECTION_LOAD_ITEMS, NULL,
      error);
  g_object_unref(service);
  if (*error != NULL) {
    return NULL;
  }

  if (secret_collection_get_locked(collection)) {
    GList *objects = g_list_append(NULL, collection);
    GList *unlocked = NULL;
    const gint n =
        secret_service_unlock_sync(secret_collection_get_service(collection),
                                   objects, NULL, &unlocked, error);
    g_list_free(objects);
    g_list_free(unlocked);
    g_object_unref(collection);
    if (*error != NULL) {
      return NULL;
    }
    if (n == 0) {
      fprintf(stderr, "%s: failed to unlock collection\n", envchain_name);
    }

    /* reload */
    secret_service_disconnect();
    service =
        secret_service_get_sync(SECRET_SERVICE_LOAD_COLLECTIONS, NULL, error);
    if (*error != NULL) {
      return NULL;
    }
    collection = secret_collection_for_alias_sync(
        service, SECRET_COLLECTION_DEFAULT, SECRET_COLLECTION_LOAD_ITEMS, NULL,
        error);
    g_object_unref(service);
    if (*error != NULL) {
      return NULL;
    }
  }

  GHashTable *attributes =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
  if (name != NULL) {
    g_hash_table_insert(attributes, g_strdup("name"), g_strdup(name));
  }
  GList *items = secret_collection_search_sync(
      collection, envchain_get_schema(), attributes,
      SECRET_SEARCH_ALL | SECRET_SEARCH_LOAD_SECRETS, NULL, error);

  g_hash_table_unref(attributes);
  g_object_unref(collection);

  return items;
}

int envchain_search_namespaces(envchain_namespace_search_callback callback,
                               G_GNUC_UNUSED void *data) {
  GError *error = NULL;

  GList *items = search_unlocked_collection(NULL, &error);
  if (error != NULL) {
    fprintf(stderr, "%s: search_unlocked_collection failed with %d: %s\n",
            envchain_name, error->code, error->message);
    g_error_free(error);
    return 1;
  }

  GList *iter;
  GHashTable *names =
      g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
  for (iter = items; iter != NULL; iter = iter->next) {
    SecretItem *item = iter->data;
    GHashTable *attrs = secret_item_get_attributes(item);
    char *name = g_strdup(g_hash_table_lookup(attrs, "name"));
    if (g_hash_table_add(names, name)) {
      callback(name, data);
    }
    g_hash_table_unref(attrs);
  }

  g_hash_table_unref(names);
  g_list_free(items);
  return 0;
}

int envchain_search_values(const char *name, envchain_search_callback callback,
                           void *data) {
  GError *error = NULL;
  GList *items = search_unlocked_collection(name, &error);
  if (error != NULL) {
    fprintf(stderr, "%s: search_unlocked_collection failed with %d: %s\n",
            envchain_name, error->code, error->message);
    g_error_free(error);
    return 1;
  }

  GList *iter;
  for (iter = items; iter != NULL; iter = iter->next) {
    SecretItem *item = iter->data;
    GHashTable *attrs = secret_item_get_attributes(item);
    char *key = g_hash_table_lookup(attrs, "key");
    SecretValue *value = secret_item_get_secret(item);
    callback(key, secret_value_get_text(value), data);
    secret_value_unref(value);
    g_hash_table_unref(attrs);
  }

  g_list_free(items);
  return 0;
}

void envchain_save_value(const char *name, const char *key, char *value,
                         int require_passphrase) {
  if (require_passphrase == 1) {
    fprintf(
        stderr,
        "%s: Sorry, `--require-passphrase' is unsupported on this platform\n",
        envchain_name);
    return;
  }

  GError *error = NULL;
  secret_password_store_sync(envchain_get_schema(), SECRET_COLLECTION_DEFAULT,
                             key, value, NULL, &error, "name", name, "key", key,
                             NULL);
  if (error != NULL) {
    fprintf(stderr, "%s: secret_password_store_sync failed with %d: %s\n",
            envchain_name, error->code, error->message);
    g_error_free(error);
  }
}
