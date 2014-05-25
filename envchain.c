/* envchain
 *
 * Copyright (c) 2014 Shota Fukumori (sora_h)
 *
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <assert.h>
#include <errno.h>

#include <mach-o/dyld.h>

#include <readline/readline.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#define ENVCHAIN_SERVICE_PREFIX "envchain-"

static const char version[] = "0.0.3";
const char *envchain_name;
SecKeychainRef envchain_keychain = NULL;

typedef void (*envchain_search_callback)(char* key, char* value, void *context);
typedef struct {
  envchain_search_callback callback;
  void *data;
} envchain_search_values_applier_data;

/* for help */

static void
envchain_abort_with_help(void)
{
  fprintf(
    stderr,
    "%s version %s\n\n"
    "Usage:\n"
    "  Add variables\n"
    "    %s (--set|-s) [--[no-]require-passphrase|-p|-P] [--noecho|-n] NAMESPACE ENV [ENV ..]\n"
    "  Execute with variables\n"
    "    %s NAMESPACE CMD [ARG ...]\n"
    "\n"
    "Options:\n"
    "  --set (-s):\n"
    "    Add keychain item of environment variable +ENV+ for namespace +NAMESPACE+.\n"
    "\n"
    "  --noecho (-n):\n"
    "    Enable noecho mode when prompting values. Requires stdin to be a terminal.\n"
    "\n"
    "  --require-passphrase (-p), --no-require-passphrase (-P):\n"
    "    Replace the item's ACL list to require passphrase (or not).\n"
    "    Leave as is when both options are omitted.\n"
    ,
    envchain_name, version, envchain_name, envchain_name
  );
  exit(2);
}

/* misc */


static void
envchain_fail_osstatus(OSStatus status)
{
  CFStringRef str;
  const char *cstr;
  str = SecCopyErrorMessageString(status, NULL);
  cstr = CFStringGetCStringPtr(str, kCFStringEncodingMacRoman);
  if (cstr == NULL) {
    fprintf(stderr, "Error: %d\n", (int)status);
  }
  else {
    fprintf(stderr, "Error: %s\n", cstr);
  }
  CFRelease(str);
  exit(10);
}


static char*
envchain_generate_service_name(const char *name)
{
  char *service_name;
  asprintf(&service_name, "%s%s", ENVCHAIN_SERVICE_PREFIX, name);
  if (service_name == NULL) {
    fprintf(stderr, "Failed to generate service_name\n");
    exit(10);
  }
  return service_name;
}

static CFStringRef
envchain_generate_service_name_cf(const char *name)
{
  return CFStringCreateWithFormat(
      NULL, NULL,
      CFSTR("%s%s"), ENVCHAIN_SERVICE_PREFIX, name
  );
}

char*
envchain_get_self_path(void)
{
  uint32_t pathlen = 0;
  char *selfpath = malloc(sizeof(char) * 255);
  char *selfrealpath;
  if (_NSGetExecutablePath(selfpath, &pathlen) < 0) {
    selfpath = realloc(selfpath, sizeof(char) * pathlen);
    if (_NSGetExecutablePath(selfpath, &pathlen) < 0) {
      fprintf(stderr, "NSGetExecutablePath something went wrong :/\n");
      exit(10);
    }
  }

  selfrealpath = realpath(selfpath, NULL);
  if (selfrealpath == NULL) {
    fprintf(stderr, "Error during retrieve executable path of itself: %s\n", strerror(errno));
    exit(1);
  }

  free(selfpath);

  return selfrealpath;
}

static CFArrayRef
envchain_self_trusted_app_list(void)
{
  char* selfpath = envchain_get_self_path();
  OSStatus status;
  SecTrustedApplicationRef app;
  CFArrayRef list = NULL;

  status = SecTrustedApplicationCreateFromPath(selfpath, &app);
  if (status != noErr) goto fail;

  SecTrustedApplicationRef apps[] = {app};
  list = CFArrayCreate(NULL, (void*)apps, 1, &kCFTypeArrayCallBacks);

fail:
  if (app != NULL) CFRelease(app);
  if (status != noErr) envchain_fail_osstatus(status);

  return list;
}


static void
envchain_search_values_applier(const void *raw_ref, void *raw_context)
{
  OSStatus status;
  envchain_search_values_applier_data *context = (envchain_search_values_applier_data*) raw_context;
  SecKeychainItemRef ref = (SecKeychainItemRef) raw_ref;

  SecKeychainAttribute attr = {kSecAccountItemAttr, 0, NULL};
  SecKeychainAttributeList list = {1, &attr};
  SecItemClass klass;
  UInt32 len, keylen = 0;
  char* rawvalue = NULL;
  char* rawkey = NULL;
  char* value = NULL;
  char* key = NULL;

  status = SecKeychainItemCopyContent(
    ref, &klass, &list, &len, (void*)&rawvalue
  );
  if (status != noErr) goto fail;

  for(UInt32 i = 0; i < list.count; i++) {
    SecKeychainAttribute attr = list.attr[i];
    if (attr.tag == kSecAccountItemAttr) {
      rawkey = (char*)attr.data;
      keylen = attr.length;

      key = malloc(keylen+1);
      if (key == NULL) goto fail;

      memcpy(key, rawkey, keylen);
      key[keylen] = '\0';

      break;
    }
  }

  if (rawkey == NULL) {
    fprintf(stderr, "Can't find account name\n");
    goto ensure;
  }

  value = malloc(len+1);
  if (value == NULL) goto fail;
  memcpy(value,rawvalue,len);
  value[len] = '\0';
  context->callback(key, value, context->data);

  goto ensure;
fail:
  fprintf(stderr, "Something wrong during searching value\n");
  if (errno) fprintf(stderr, "errno: %s\n", strerror(errno));
ensure:
  if (value) {
    memset(value, 0, len);
    free(value);
  }
  if (key) {
    memset(key, 0, keylen);
    free(key);
  }
  SecKeychainItemFreeContent(&list, rawvalue);
  return;
}

int
envchain_search_values(const char *name, envchain_search_callback callback, void *data)
{
  OSStatus status;
  CFStringRef service_name = envchain_generate_service_name_cf(name);
  CFArrayRef items = NULL;

  const void *query_keys[] = {
    kSecClass, kSecAttrService,
    kSecReturnRef, kSecMatchLimit
  };
  const void *query_vals[] = {
    kSecClassGenericPassword, service_name,
    kCFBooleanTrue, kSecMatchLimitAll
  };

  CFDictionaryRef query = CFDictionaryCreate(kCFAllocatorDefault,
      query_keys, query_vals, sizeof(query_keys) / sizeof(query_keys[0]),
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

  status = SecItemCopyMatching(query, (CFTypeRef *)&items);
  if (status != errSecItemNotFound && status != noErr) goto fail;

  if (status == errSecItemNotFound || CFArrayGetCount(items) == 0) {
    fprintf(stderr,
      "WARNING: namespace `%s` not defined.\n"
      "         You can set via running `%s --set %s SOME_ENV_NAME`.\n\n",
      name, envchain_name, name
    );
    return 1;
  }
  
  envchain_search_values_applier_data context = {callback, data};
  CFArrayApplyFunction(
    items, CFRangeMake(0, CFArrayGetCount(items)),
    &envchain_search_values_applier, &context
  );

fail:
  if (items != NULL) CFRelease(items);
  if (query != NULL) CFRelease(query);
  if (service_name != NULL) CFRelease(service_name);
  if (status != noErr) envchain_fail_osstatus(status);

  return 0;
}


int
envchain_find_value(const char *name, const char *key, SecKeychainItemRef *ref)
{
  OSStatus status;
  char *service_name = envchain_generate_service_name(name);

  status = SecKeychainFindGenericPassword(
    envchain_keychain,
    strlen(service_name), service_name,
    strlen(key), key,
    NULL, NULL,
    ref
  );

  free(service_name);

  if (status != noErr && status != errSecItemNotFound) {
    if (ref != NULL) CFRelease(ref);
    envchain_fail_osstatus(status);
  }

  return status == errSecItemNotFound ? 0 : 1;
}

void
envchain_save_value(const char *name, const char *key, char *value, int require_passphrase)
{
  char *service_name = envchain_generate_service_name(name);
  OSStatus status;
  SecKeychainItemRef ref = NULL;
  SecAccessRef access_ref = NULL;
  CFArrayRef acl_list = nil;

  if (envchain_find_value(name, key, &ref) == 0) {
    status = SecKeychainAddGenericPassword(
      envchain_keychain,
      strlen(service_name), service_name,
      strlen(key), key,
      strlen(value), value,
      &ref
    );
  }
  else {
    status = SecKeychainItemModifyAttributesAndData(
      ref,
      NULL,
      strlen(value), value
    );
  }

  free(service_name);

  if (status != noErr) goto fail;

  if (require_passphrase >= 0) {
    CFArrayRef app_list = NULL;
    CFStringRef desc = NULL;

    status = SecKeychainItemCopyAccess(ref, &access_ref);
    if (status != noErr) goto fail;

    acl_list = SecAccessCopyMatchingACLList(
      access_ref, kSecACLAuthorizationDecrypt
    );
    SecACLRef acl = (SecACLRef)CFArrayGetValueAtIndex(acl_list, 0);

    if (acl == NULL) {
      fprintf(stderr, "error: There's no ACL?\n");
      goto passfail;
    }

    SecKeychainPromptSelector prompt;
    status = SecACLCopyContents(acl, &app_list, &desc, &prompt);
    if (status != noErr) goto passfail;
    if (app_list != NULL) CFRelease(app_list);

    printf("%16x", prompt);
    if(require_passphrase == 1) {
      if (prompt == 0) prompt = 0x100;
      prompt |= kSecKeychainPromptRequirePassphase;
      app_list = CFArrayCreate(NULL, NULL, 0, &kCFTypeArrayCallBacks);
    }
    else {
      prompt = 0;
      app_list = envchain_self_trusted_app_list();
    }

    printf("%16x", prompt);
    status = SecACLSetContents(acl, app_list, desc, prompt);
    if (status != noErr) goto passfail;

    status = SecKeychainItemSetAccess(ref, access_ref);

passfail:
    if (app_list != NULL) CFRelease(app_list);
    if (desc != NULL) CFRelease(desc);
    if (status != noErr) goto fail;
  }

fail:
  if (ref != NULL) { CFRelease(ref); }
  if (access_ref != NULL) { CFRelease(access_ref); }
  if (acl_list != NULL) { CFRelease(acl_list); }
  if (status != noErr) envchain_fail_osstatus(status);

  return;
}

/* functions for --set */

char*
envchain_noecho_read(char* prompt)
{
  struct termios term, term_orig;
  char* str = NULL;
  ssize_t len;
  size_t n;

  if (tcgetattr(STDIN_FILENO, &term) < 0) {
    if (errno == ENOTTY) {
      fprintf(stderr, "--noecho (-n) requires stdin to be a terminal\n");
    }
    else {
      fprintf(stderr, "oops when attempted to read: %s\n", strerror(errno));
    }
    return NULL;
  }

  term_orig = term;
  term.c_lflag &= ~ECHO;
  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term) < 0) {
    fprintf(stderr, "tcsetattr failed\n");
    exit(10);
  }

  printf("%s (noecho):", prompt);
  len = getline(&str, &n, stdin);

  if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &term_orig) < 0) {
    fprintf(stderr, "tcsetattr restore failed\n");
    exit(10);
  }

  if (0 < len && str[len-1] == '\n')
    str[len - 1] = '\0';

  printf("\n");

  return str;
}


static char*
envchain_ask_value(const char* name, const char* key, int noecho)
{
  char *prompt, *line;
  asprintf(&prompt, "%s.%s", name, key);

  if (noecho) {
    line = envchain_noecho_read(prompt);
  }
  else {
    printf("%s", prompt);
    line = readline(": ");
  }

  free(prompt);
  return line;
}

int
envchain_set(int argc, const char **argv)
{
  int noecho = 0;
  int require_passphrase = -1;
  const char *name, *key;
  char *value;

  while (2 < argc) {
    if (argv[0][0] != '-') break;

    if (strcmp(argv[0], "-n") == 0 || strcmp(argv[0], "--noecho") == 0) {
      argv++; argc--;
      noecho = 1;
    }
    else if (strcmp(argv[0], "-p") == 0 || strcmp(argv[0], "--require-passphrase") == 0) {
      argv++; argc--;
      require_passphrase = 1;
    }
    else if (strcmp(argv[0], "-P") == 0 || strcmp(argv[0], "--no-require-passphrase") == 0) {
      argv++; argc--;
      require_passphrase = 0;
    }
    else {
      fprintf(stderr, "Unknown option: %s", argv[0]);
      return 1;
    }
  }
  if (argc < 2) envchain_abort_with_help();

  name = argv[0];
  argv++; argc--;

  while(0 < argc) {
    key = argv[0];
    argv++; argc--;

    value = envchain_ask_value(name, key, noecho);
    if (value == NULL) return 1;

    envchain_save_value(name, key, value, require_passphrase);
  }

  return 0;
}

/* functions for exec mode */

static void
envchain_exec_value_callback(char* key, char* value, void *context)
{
  (void)context; /* silence warning */

  setenv(key, value, 1);
}

int
envchain_exec(int argc, const char **argv)
{
  if (argc < 2) envchain_abort_with_help();

  const char *name, *exe;
  char **args;

  name = argv[0];
  exe = argv[1];
  argv++; argc--;
  argv++; argc--;

  envchain_search_values(name, &envchain_exec_value_callback, NULL);

  int len = (2+argc);
  args = malloc(sizeof(char*) * len);
  args[0] = (char*)exe;
  args[len-1] = NULL;
  if (0 < argc) memcpy(args+1, argv, sizeof(char*) * argc);

  if (execvp(exe, args) < 0) {
    fprintf(stderr, "execvp failed: %s\n", strerror(errno));
    return 1;
  }
  return 0;
}

/* entry point */

int
main(int argc, const char **argv)
{
  envchain_name = argv[0];
  if (argc < 2) envchain_abort_with_help();
  argv++; argc--;

  if (strcmp(argv[0], "--set") == 0 || strcmp(argv[0], "-s") == 0) {
    argv++; argc--;
    return envchain_set(argc, argv);
  }
  else if (argv[0][0] == '-') {
    fprintf(stderr, "Unknown option %s", argv[0]);
    return 2;
  }
  else {
    return envchain_exec(argc, argv);
  }
}
