#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include "dns_mask.h"

#if defined(PLATFORM_PS4)
#include <ps4/kernel.h>
#include <ps4/klog.h>
#elif defined(PLATFORM_PS5)
#include <ps5/kernel.h>
#include <ps5/klog.h>
#define PAYLOAD_PROCESS_LABEL "nanodns-encore"
#else
#error "Define PLATFORM_PS4 or PLATFORM_PS5"
#endif

#define APP_NAME "NanoDNS"
#define APP_VERSION "0.4-13.60.3"
#define APP_COPYRIGHT "(c) Drakmor"
#define DATA_DIR "/data/nanodns"
#define CONFIG_PATH DATA_DIR "/nanodns.ini"
#define DEFAULT_LOG_PATH DATA_DIR "/nanodns.log"
#define LOG_MAX_BYTES (4u * 1024u * 1024u)
#define DNS_PORT 53
#define MAX_DNS_PACKET 4096
#define MAX_UPSTREAMS 8
#define MAX_CONFIG_FILE_BYTES (4096u * 1024u)
#define MAX_RULES 4096u
#define MAX_EXCEPTIONS 4096u
#define INITIAL_RULE_CAPACITY 16u
#define INITIAL_EXCEPTION_CAPACITY 8u
#define MAX_CONFIG_WARNINGS 128
#define MAX_CONFIG_WARNING_LEN 256
#define MAX_DOMAIN_LEN 256
#define MAX_LOG_PATH 256
#define DEFAULT_TIMEOUT_MS 1500
#define LISTENER_RETRY_MS 1000
#define OVERRIDE_TTL 60
#define PRIVILEGED_AUTHID 0x4801000000000013L

enum {
  SERVER_LISTENER_IPV4 = 0,
  SERVER_LISTENER_IPV6 = 1,
  SERVER_LISTENER_COUNT = 2,
};

int sceNetInit(void);
int sceNetPoolCreate(const char *name, int size, int flags);
int sceNetPoolDestroy(int memid);
int sceNetTerm(void);
int sceKernelSendNotificationRequest(int, void *, size_t, int);

typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;

typedef struct {
  struct in_addr addr;
  char text[INET_ADDRSTRLEN];
} upstream_t;

typedef struct {
  char mask[MAX_DOMAIN_LEN];
  struct in_addr addr;
  char text[INET_ADDRSTRLEN];
} override_rule_t;

typedef struct {
  char mask[MAX_DOMAIN_LEN];
} exception_rule_t;

typedef struct {
  char text[MAX_CONFIG_WARNING_LEN];
} config_warning_t;

typedef struct {
  upstream_t upstreams[MAX_UPSTREAMS];
  size_t upstream_count;
  override_rule_t *rules;
  size_t rule_count;
  size_t rule_capacity;
  exception_rule_t *exceptions;
  size_t exception_count;
  size_t exception_capacity;
  int timeout_ms;
  int debug_enabled;
  int quiet_enabled;
  struct in_addr bind_addr;
  char bind_text[INET_ADDRSTRLEN];
  bool bind6_enabled;
  struct in6_addr bind6_addr;
  char bind6_text[INET6_ADDRSTRLEN];
  char log_path[MAX_LOG_PATH];
  config_warning_t warnings[MAX_CONFIG_WARNINGS];
  size_t warning_count;
} app_config_t;

typedef struct {
  uint16_t id;
  uint16_t flags;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
  size_t qname_offset;
  size_t question_end;
  char qname[MAX_DOMAIN_LEN];
  uint16_t qtype;
  uint16_t qclass;
} dns_question_t;

typedef struct {
  int fd;
  int family;
  const char *name;
  bool retry_enabled;
  int64_t retry_at_ms;
} server_listener_t;

static volatile sig_atomic_t g_running = 1;
static int g_libnet_mem_id = -1;
static int g_debug_enabled = 1;
static FILE *g_log_file = NULL;
static char g_log_active_path[MAX_LOG_PATH];
static size_t g_log_bytes = 0;

static const char *k_default_config =
    "# nanoDNS 13.60 baseline: https://github.com/niakw/nanodns-console-blocklist\n"
    "# Original nanoDNS by Drakmor: https://github.com/drakmor/nanoDNS\n"
    "# nanoDNS Console Blocklist — selective multi-console profile v3\n"
    "# Updated: 2026-10-10 | Tested configuration: nanoDNS v0.4 on PS5 firmware 13.60\n"
    "# Community-maintained best-effort DNS filtering; NOT a firewall.\n"
    "# Installed path: /data/nanodns/nanodns.ini\n"
    "# 124 DNS override rules; no exceptions. Does not block unrelated Internet by default.\n"
    "# WARNING: brand-wide masks and the Akamai exact alias may cause collateral blocking.\n"
    "# DNS traffic bypass, direct IP traffic and pre-payload traffic are OUT OF SCOPE.\n"
    "\n"
    "[general]\n"
    "log=/data/nanodns/nanodns.log\n"
    "debug=0\n"
    "quiet=0\n"
    "bind=127.0.0.1\n"
    "bind6=::1\n"
    "\n"
    "[upstream]\n"
    "server=76.76.2.0\n"
    "server=76.76.10.0\n"
    "server=94.140.14.140\n"
    "server=94.140.14.141\n"
    "timeout_ms=1500\n"
    "\n"
    "[overrides]\n"
    "# SONY / PLAYSTATION / SIE\n"
    "*playstation*=0.0.0.0\n"
    "*sony*=0.0.0.0\n"
    "*psndl*=0.0.0.0\n"
    "*gaikai*=0.0.0.0\n"
    "*ribob01*=0.0.0.0\n"
    "*psn-rsc*=0.0.0.0\n"
    "*siedev*=0.0.0.0\n"
    "*sie-rd*=0.0.0.0\n"
    "*scei*=0.0.0.0\n"
    "*scea*=0.0.0.0\n"
    "sie.com=0.0.0.0\n"
    "*.sie.com=0.0.0.0\n"
    "# Exact historical PlayStation CDN alias on shared Akamai infrastructure.\n"
    "a192.d.akamai.net=0.0.0.0\n"
    "psn.akadns99.net=0.0.0.0\n"
    "*.psn.akadns99.net=0.0.0.0\n"
    "\n"
    "# EPIC GAMES / FORTNITE / EASY ANTI-CHEAT\n"
    "epicgames.com=0.0.0.0\n"
    "*.epicgames.com=0.0.0.0\n"
    "epicgames.dev=0.0.0.0\n"
    "*.epicgames.dev=0.0.0.0\n"
    "fortnite.com=0.0.0.0\n"
    "*.fortnite.com=0.0.0.0\n"
    "unrealengine.com=0.0.0.0\n"
    "*.unrealengine.com=0.0.0.0\n"
    "easyanticheat.net=0.0.0.0\n"
    "*.easyanticheat.net=0.0.0.0\n"
    "easy.ac=0.0.0.0\n"
    "*.easy.ac=0.0.0.0\n"
    "\n"
    "# ROCKSTAR / TAKE-TWO / 2K\n"
    "rsgameservices.com=0.0.0.0\n"
    "*.rsgameservices.com=0.0.0.0\n"
    "rockstargames.com=0.0.0.0\n"
    "*.rockstargames.com=0.0.0.0\n"
    "rockstarservices.com=0.0.0.0\n"
    "*.rockstarservices.com=0.0.0.0\n"
    "take2games.com=0.0.0.0\n"
    "*.take2games.com=0.0.0.0\n"
    "2k.com=0.0.0.0\n"
    "*.2k.com=0.0.0.0\n"
    "2kcoretech.online=0.0.0.0\n"
    "*.2kcoretech.online=0.0.0.0\n"
    "\n"
    "# CD PROJEKT / GOG\n"
    "gog.com=0.0.0.0\n"
    "*.gog.com=0.0.0.0\n"
    "gogcdn.net=0.0.0.0\n"
    "*.gogcdn.net=0.0.0.0\n"
    "gog-statics.com=0.0.0.0\n"
    "*.gog-statics.com=0.0.0.0\n"
    "gogalaxy.com=0.0.0.0\n"
    "*.gogalaxy.com=0.0.0.0\n"
    "cdpred.services=0.0.0.0\n"
    "*.cdpred.services=0.0.0.0\n"
    "cdprojekt.com=0.0.0.0\n"
    "*.cdprojekt.com=0.0.0.0\n"
    "cdprojektred.com=0.0.0.0\n"
    "*.cdprojektred.com=0.0.0.0\n"
    "cyberpunk.net=0.0.0.0\n"
    "*.cyberpunk.net=0.0.0.0\n"
    "\n"
    "# NINTENDO (Wii / DS / 3DS / Wii U / Switch / Switch 2 branded endpoints)\n"
    "*nintendo*=0.0.0.0\n"
    "*nintendowifi*=0.0.0.0\n"
    "wii.com=0.0.0.0\n"
    "*.wii.com=0.0.0.0\n"
    "\n"
    "# EA / EA SPORTS / ORIGIN\n"
    "ea.com=0.0.0.0\n"
    "*.ea.com=0.0.0.0\n"
    "ea.net=0.0.0.0\n"
    "*.ea.net=0.0.0.0\n"
    "easports.com=0.0.0.0\n"
    "*.easports.com=0.0.0.0\n"
    "easportsfc.com=0.0.0.0\n"
    "*.easportsfc.com=0.0.0.0\n"
    "eaplay.com=0.0.0.0\n"
    "*.eaplay.com=0.0.0.0\n"
    "origin.com=0.0.0.0\n"
    "*.origin.com=0.0.0.0\n"
    "\n"
    "# UBISOFT\n"
    "ubisoft.com=0.0.0.0\n"
    "*.ubisoft.com=0.0.0.0\n"
    "ubi.com=0.0.0.0\n"
    "*.ubi.com=0.0.0.0\n"
    "ubisoftconnect.com=0.0.0.0\n"
    "*.ubisoftconnect.com=0.0.0.0\n"
    "ubi-services.com=0.0.0.0\n"
    "*.ubi-services.com=0.0.0.0\n"
    "\n"
    "# SEGA\n"
    "sega.com=0.0.0.0\n"
    "*.sega.com=0.0.0.0\n"
    "sega.co.jp=0.0.0.0\n"
    "*.sega.co.jp=0.0.0.0\n"
    "\n"
    "# XBOX (original / 360 / One / Series, including some legacy CDN aliases)\n"
    "xbox.com=0.0.0.0\n"
    "*.xbox.com=0.0.0.0\n"
    "xboxlive.com=0.0.0.0\n"
    "*.xboxlive.com=0.0.0.0\n"
    "gamepass.com=0.0.0.0\n"
    "*.gamepass.com=0.0.0.0\n"
    "xboxservices.com=0.0.0.0\n"
    "*.xboxservices.com=0.0.0.0\n"
    "xboxlive.com.akadns.net=0.0.0.0\n"
    "*.xboxlive.com.akadns.net=0.0.0.0\n"
    "xboxlive.com.edgesuite.net=0.0.0.0\n"
    "*.xboxlive.com.edgesuite.net=0.0.0.0\n"
    "xboxlive.com.akamaized.net=0.0.0.0\n"
    "*.xboxlive.com.akamaized.net=0.0.0.0\n"
    "xboxlive.com.nsatc.net=0.0.0.0\n"
    "*.xboxlive.com.nsatc.net=0.0.0.0\n"
    "xboxlive.com-c.edgekey.net=0.0.0.0\n"
    "*.xboxlive.com-c.edgekey.net=0.0.0.0\n"
    "xboxlive.wns.windows.com=0.0.0.0\n"
    "xboxlive.download.akamai.com=0.0.0.0\n"
    "xcloud.dedicated.msn.com=0.0.0.0\n"
    "xsvc.microsoft.com=0.0.0.0\n"
    "*.xsvc.microsoft.com=0.0.0.0\n"
    "xboxrc.com=0.0.0.0\n"
    "*.xboxrc.com=0.0.0.0\n"
    "xboxlive.ipv6.microsoft.com.akadns.net=0.0.0.0\n"
    "xboxservices.com.akadns.net=0.0.0.0\n"
    "*.xboxservices.com.akadns.net=0.0.0.0\n"
    "xboxlive.com-c.edgekey.net.globalredir.akadns.net=0.0.0.0\n"
    "\n"
    "# OTHER GAME PUBLISHERS / PC PLATFORMS\n"
    "steampowered.com=0.0.0.0\n"
    "*.steampowered.com=0.0.0.0\n"
    "steamcommunity.com=0.0.0.0\n"
    "*.steamcommunity.com=0.0.0.0\n"
    "valvesoftware.com=0.0.0.0\n"
    "*.valvesoftware.com=0.0.0.0\n"
    "capcom.com=0.0.0.0\n"
    "*.capcom.com=0.0.0.0\n"
    "square-enix.com=0.0.0.0\n"
    "*.square-enix.com=0.0.0.0\n"
    "bandainamcoent.com=0.0.0.0\n"
    "*.bandainamcoent.com=0.0.0.0\n"
    "\n"
    "[exceptions]\n"
    "# None. Add exceptions only after auditing their impact on your threat model.\n";

/* Mandatory rules from nanodns-console-blocklist, checked before all
 * user exceptions. tests/test_policy.py rejects drift from nanodns.ini. */
static const char *const k_protected_masks[] = {
    "*playstation*",
    "*sony*",
    "*psndl*",
    "*gaikai*",
    "*ribob01*",
    "*psn-rsc*",
    "*siedev*",
    "*sie-rd*",
    "*scei*",
    "*scea*",
    "sie.com",
    "*.sie.com",
    "a192.d.akamai.net",
    "psn.akadns99.net",
    "*.psn.akadns99.net",
    "epicgames.com",
    "*.epicgames.com",
    "epicgames.dev",
    "*.epicgames.dev",
    "fortnite.com",
    "*.fortnite.com",
    "unrealengine.com",
    "*.unrealengine.com",
    "easyanticheat.net",
    "*.easyanticheat.net",
    "easy.ac",
    "*.easy.ac",
    "rsgameservices.com",
    "*.rsgameservices.com",
    "rockstargames.com",
    "*.rockstargames.com",
    "rockstarservices.com",
    "*.rockstarservices.com",
    "take2games.com",
    "*.take2games.com",
    "2k.com",
    "*.2k.com",
    "2kcoretech.online",
    "*.2kcoretech.online",
    "gog.com",
    "*.gog.com",
    "gogcdn.net",
    "*.gogcdn.net",
    "gog-statics.com",
    "*.gog-statics.com",
    "gogalaxy.com",
    "*.gogalaxy.com",
    "cdpred.services",
    "*.cdpred.services",
    "cdprojekt.com",
    "*.cdprojekt.com",
    "cdprojektred.com",
    "*.cdprojektred.com",
    "cyberpunk.net",
    "*.cyberpunk.net",
    "*nintendo*",
    "*nintendowifi*",
    "wii.com",
    "*.wii.com",
    "ea.com",
    "*.ea.com",
    "ea.net",
    "*.ea.net",
    "easports.com",
    "*.easports.com",
    "easportsfc.com",
    "*.easportsfc.com",
    "eaplay.com",
    "*.eaplay.com",
    "origin.com",
    "*.origin.com",
    "ubisoft.com",
    "*.ubisoft.com",
    "ubi.com",
    "*.ubi.com",
    "ubisoftconnect.com",
    "*.ubisoftconnect.com",
    "ubi-services.com",
    "*.ubi-services.com",
    "sega.com",
    "*.sega.com",
    "sega.co.jp",
    "*.sega.co.jp",
    "xbox.com",
    "*.xbox.com",
    "xboxlive.com",
    "*.xboxlive.com",
    "gamepass.com",
    "*.gamepass.com",
    "xboxservices.com",
    "*.xboxservices.com",
    "xboxlive.com.akadns.net",
    "*.xboxlive.com.akadns.net",
    "xboxlive.com.edgesuite.net",
    "*.xboxlive.com.edgesuite.net",
    "xboxlive.com.akamaized.net",
    "*.xboxlive.com.akamaized.net",
    "xboxlive.com.nsatc.net",
    "*.xboxlive.com.nsatc.net",
    "xboxlive.com-c.edgekey.net",
    "*.xboxlive.com-c.edgekey.net",
    "xboxlive.wns.windows.com",
    "xboxlive.download.akamai.com",
    "xcloud.dedicated.msn.com",
    "xsvc.microsoft.com",
    "*.xsvc.microsoft.com",
    "xboxrc.com",
    "*.xboxrc.com",
    "xboxlive.ipv6.microsoft.com.akadns.net",
    "xboxservices.com.akadns.net",
    "*.xboxservices.com.akadns.net",
    "xboxlive.com-c.edgekey.net.globalredir.akadns.net",
    "steampowered.com",
    "*.steampowered.com",
    "steamcommunity.com",
    "*.steamcommunity.com",
    "valvesoftware.com",
    "*.valvesoftware.com",
    "capcom.com",
    "*.capcom.com",
    "square-enix.com",
    "*.square-enix.com",
    "bandainamcoent.com",
    "*.bandainamcoent.com",
};
#define PROTECTED_RULE_COUNT (sizeof(k_protected_masks) / sizeof(k_protected_masks[0]))

static void
logger_rotate_if_full(void) {
  char previous[MAX_LOG_PATH + 16];
  int written;

  if(g_log_file == NULL || g_log_bytes < LOG_MAX_BYTES) {
    return;
  }
  fclose(g_log_file);
  g_log_file = NULL;
  written = snprintf(previous, sizeof(previous), "%s.previous",
                     g_log_active_path);
  if(written < 0 || (size_t)written >= sizeof(previous)) {
    return;
  }
  (void)rename(g_log_active_path, previous);
  g_log_file = fopen(g_log_active_path, "w");
  g_log_bytes = 0;
  if(g_log_file != NULL) {
    setvbuf(g_log_file, NULL, _IOLBF, 0);
  }
}

static void
log_emit_direct(const char *buf, int to_debug) {
  if(g_log_file != NULL) {
    if(fputs(buf, g_log_file) == EOF || fflush(g_log_file) == EOF) {
      /* Do not let logging failures break local DNS deny rules. */
      fclose(g_log_file);
      g_log_file = NULL;
    } else {
      g_log_bytes += strlen(buf);
      logger_rotate_if_full();
    }
  }

  if(to_debug) {
    fputs(buf, stdout);
    fflush(stdout);
    klog_printf("%s", buf);
  }
}

static int
logger_init(const app_config_t *cfg) {
  char buf[512];
  char previous[MAX_LOG_PATH + 16];
  int written;

  if(g_log_file != NULL) {
    fclose(g_log_file);
    g_log_file = NULL;
  }

  g_debug_enabled = cfg->debug_enabled ? 1 : 0;
  snprintf(g_log_active_path, sizeof(g_log_active_path), "%s",
           cfg->log_path);
  written = snprintf(previous, sizeof(previous), "%s.previous",
                     g_log_active_path);
  if(written >= 0 && (size_t)written < sizeof(previous)) {
    /* Keep the last session's log instead of silently truncating it. */
    (void)rename(g_log_active_path, previous);
  }
  g_log_file = fopen(cfg->log_path, "w");
  g_log_bytes = 0;
  if(g_log_file == NULL) {
    if(!g_debug_enabled) {
      g_debug_enabled = 1;
    }
    snprintf(buf, sizeof(buf), "[nanodns] failed to open log file %s: %s\n",
             cfg->log_path, strerror(errno));
    log_emit_direct(buf, g_debug_enabled);
    return -1;
  }

  setvbuf(g_log_file, NULL, _IOLBF, 0);
  return 0;
}

static void
logger_fini(void) {
  if(g_log_file != NULL) {
    fclose(g_log_file);
    g_log_file = NULL;
  }
}

static void
log_printf(const char *fmt, ...) {
  char buf[1024];
  va_list ap;
  int written;

  va_start(ap, fmt);
  written = vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  if(written < 0) {
    return;
  }

  log_emit_direct(buf, g_debug_enabled);
}

static void
log_errno(const char *what) {
  log_printf("[nanodns] %s: %s\n", what, strerror(errno));
}

static const char *
dns_type_to_string(uint16_t qtype) {
  switch(qtype) {
  case 1:
    return "A";
  case 2:
    return "NS";
  case 5:
    return "CNAME";
  case 6:
    return "SOA";
  case 12:
    return "PTR";
  case 15:
    return "MX";
  case 16:
    return "TXT";
  case 28:
    return "AAAA";
  case 33:
    return "SRV";
  case 41:
    return "OPT";
  case 255:
    return "ANY";
  default:
    return "OTHER";
  }
}

static const char *
dns_rcode_to_string(uint16_t rcode) {
  switch(rcode) {
  case 0:
    return "NOERROR";
  case 1:
    return "FORMERR";
  case 2:
    return "SERVFAIL";
  case 3:
    return "NXDOMAIN";
  case 4:
    return "NOTIMP";
  case 5:
    return "REFUSED";
  default:
    return "OTHER";
  }
}

static uint16_t
read_u16(const uint8_t *ptr) {
  return (uint16_t)(((uint16_t)ptr[0] << 8) | ptr[1]);
}

static uint32_t
read_u32(const uint8_t *ptr) {
  return ((uint32_t)ptr[0] << 24) | ((uint32_t)ptr[1] << 16) |
         ((uint32_t)ptr[2] << 8) | ptr[3];
}

static void
write_u16(uint8_t *ptr, uint16_t value) {
  ptr[0] = (uint8_t)((value >> 8) & 0xff);
  ptr[1] = (uint8_t)(value & 0xff);
}

static void
write_u32(uint8_t *ptr, uint32_t value) {
  ptr[0] = (uint8_t)((value >> 24) & 0xff);
  ptr[1] = (uint8_t)((value >> 16) & 0xff);
  ptr[2] = (uint8_t)((value >> 8) & 0xff);
  ptr[3] = (uint8_t)(value & 0xff);
}

static char *
ltrim(char *s) {
  while(*s && isspace((unsigned char)*s)) {
    ++s;
  }

  return s;
}

static void
rtrim(char *s) {
  size_t len = strlen(s);

  while(len > 0 && isspace((unsigned char)s[len - 1])) {
    s[--len] = '\0';
  }
}

static char *
trim(char *s) {
  s = ltrim(s);
  rtrim(s);
  return s;
}

static void
strip_inline_comment(char *s) {
  char *hash = strchr(s, '#');
  char *semi = strchr(s, ';');
  char *cut = NULL;

  if(hash && semi) {
    cut = hash < semi ? hash : semi;
  } else if(hash) {
    cut = hash;
  } else if(semi) {
    cut = semi;
  }

  if(cut) {
    *cut = '\0';
    rtrim(s);
  }
}

static void
normalize_domain(const char *input, char *output, size_t output_size) {
  size_t out = 0;

  if(output_size == 0) {
    return;
  }

  for(; *input != '\0' && out + 1 < output_size; ++input) {
    output[out++] = (char)tolower((unsigned char)*input);
  }

  while(out > 0 && output[out - 1] == '.') {
    --out;
  }

  output[out] = '\0';
}

static int
parse_int_strict(const char *text, int *value) {
  char *end = NULL;
  long parsed;

  errno = 0;
  parsed = strtol(text, &end, 10);
  if(errno != 0 || end == text || *end != '\0' || parsed < INT_MIN ||
     parsed > INT_MAX) {
    return -1;
  }

  *value = (int)parsed;
  return 0;
}

static void
config_add_warning(app_config_t *cfg, const char *fmt, ...) {
  va_list ap;

  if(cfg->warning_count >= MAX_CONFIG_WARNINGS) {
    return;
  }

  va_start(ap, fmt);
  vsnprintf(cfg->warnings[cfg->warning_count].text, MAX_CONFIG_WARNING_LEN, fmt,
            ap);
  va_end(ap);
  ++cfg->warning_count;
}

static int
config_set_bind_address(app_config_t *cfg, const char *ip) {
  if(inet_pton(AF_INET, ip, &cfg->bind_addr) != 1) {
    return -1;
  }

  snprintf(cfg->bind_text, sizeof(cfg->bind_text), "%s", ip);
  return 0;
}

static int
config_set_bind6_address(app_config_t *cfg, const char *ip) {
  if(inet_pton(AF_INET6, ip, &cfg->bind6_addr) != 1) {
    return -1;
  }

  cfg->bind6_enabled = true;
  snprintf(cfg->bind6_text, sizeof(cfg->bind6_text), "%s", ip);
  return 0;
}

static void
config_disable_bind6_address(app_config_t *cfg) {
  cfg->bind6_enabled = false;
  memset(&cfg->bind6_addr, 0, sizeof(cfg->bind6_addr));
  snprintf(cfg->bind6_text, sizeof(cfg->bind6_text), "off");
}

static bool
config_value_is_disabled(const char *value) {
  return !strcasecmp(value, "off") || !strcasecmp(value, "disabled") ||
         !strcasecmp(value, "none") || !strcasecmp(value, "no") ||
         !strcasecmp(value, "false") || !strcmp(value, "0");
}

static void
config_set_defaults(app_config_t *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
  cfg->debug_enabled = 0;
  cfg->quiet_enabled = 0;
  (void)config_set_bind_address(cfg, "127.0.0.1");
  (void)config_set_bind6_address(cfg, "::1");
  snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", DEFAULT_LOG_PATH);
}

static int
config_add_upstream(app_config_t *cfg, const char *ip) {
  upstream_t *upstream;

  if(cfg->upstream_count >= MAX_UPSTREAMS) {
    return -1;
  }

  upstream = &cfg->upstreams[cfg->upstream_count];
  if(inet_pton(AF_INET, ip, &upstream->addr) != 1) {
    return -1;
  }

  snprintf(upstream->text, sizeof(upstream->text), "%s", ip);
  ++cfg->upstream_count;
  return 0;
}

static void
config_release(app_config_t *cfg) {
  free(cfg->rules);
  cfg->rules = NULL;
  cfg->rule_count = 0;
  cfg->rule_capacity = 0;
  free(cfg->exceptions);
  cfg->exceptions = NULL;
  cfg->exception_count = 0;
  cfg->exception_capacity = 0;
}

static int
config_add_rule(app_config_t *cfg, const char *mask, const char *ip) {
  override_rule_t *rule;

  if(cfg->rule_count >= MAX_RULES) {
    return -5;
  }

  if(strlen(mask) >= sizeof(((override_rule_t *)0)->mask)) {
    return -3;
  }

  if(cfg->rule_count == cfg->rule_capacity) {
    size_t next_capacity =
        cfg->rule_capacity == 0 ? INITIAL_RULE_CAPACITY : cfg->rule_capacity * 2u;
    if(next_capacity < cfg->rule_capacity ||
       next_capacity > SIZE_MAX / sizeof(*cfg->rules)) {
      return -4;
    }
    override_rule_t *next =
        realloc(cfg->rules, next_capacity * sizeof(*cfg->rules));
    if(next == NULL) {
      return -4;
    }
    cfg->rules = next;
    cfg->rule_capacity = next_capacity;
  }

  rule = &cfg->rules[cfg->rule_count];
  if(inet_pton(AF_INET, ip, &rule->addr) != 1) {
    return -2;
  }

  snprintf(rule->mask, sizeof(rule->mask), "%s", mask);
  normalize_domain(rule->mask, rule->mask, sizeof(rule->mask));
  snprintf(rule->text, sizeof(rule->text), "%s", ip);
  ++cfg->rule_count;
  return 0;
}

static int
config_add_exception(app_config_t *cfg, const char *mask) {
  exception_rule_t *rule;

  if(cfg->exception_count >= MAX_EXCEPTIONS) {
    return -5;
  }

  if(strlen(mask) >= sizeof(((exception_rule_t *)0)->mask)) {
    return -3;
  }

  if(cfg->exception_count == cfg->exception_capacity) {
    size_t next_capacity =
        cfg->exception_capacity == 0 ? INITIAL_EXCEPTION_CAPACITY :
        cfg->exception_capacity * 2u;
    if(next_capacity < cfg->exception_capacity ||
       next_capacity > SIZE_MAX / sizeof(*cfg->exceptions)) {
      return -4;
    }
    exception_rule_t *next =
        realloc(cfg->exceptions, next_capacity * sizeof(*cfg->exceptions));
    if(next == NULL) {
      return -4;
    }
    cfg->exceptions = next;
    cfg->exception_capacity = next_capacity;
  }

  rule = &cfg->exceptions[cfg->exception_count];
  snprintf(rule->mask, sizeof(rule->mask), "%s", mask);
  normalize_domain(rule->mask, rule->mask, sizeof(rule->mask));
  ++cfg->exception_count;
  return 0;
}

/* No built-in exceptions: protected domains must never be forwarded. */

static void
config_apply_builtin_upstreams(app_config_t *cfg) {
  cfg->upstream_count = 0;
  (void)config_add_upstream(cfg, "76.76.2.0");
  (void)config_add_upstream(cfg, "76.76.10.0");
  (void)config_add_upstream(cfg, "94.140.14.140");
  (void)config_add_upstream(cfg, "94.140.14.141");
}

static int
config_apply_builtin_overrides(app_config_t *cfg) {
  cfg->rule_count = 0;
  for(size_t i = 0; i < PROTECTED_RULE_COUNT; ++i) {
    if(config_add_rule(cfg, k_protected_masks[i], "0.0.0.0") != 0) {
      return -1;
    }
  }
  return 0;
}

static int
ensure_runtime_dir_exists(const char *path) {
  struct stat st;

  if(stat(path, &st) == 0) {
    if(S_ISDIR(st.st_mode)) {
      return 0;
    }

    errno = ENOTDIR;
    return -1;
  }

  if(mkdir(path, 0777) != 0) {
    return -1;
  }

  return 1;
}

static int
ensure_default_config_exists(const char *path) {
  FILE *fp;
  int fd;

  /* O_EXCL makes the existence check and creation a single operation.
   * Never truncate an existing INI (including one swapped in by another
   * process). O_NOFOLLOW also rejects a symlink at the final component. */
  fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
  if(fd < 0) {
    if(errno == EEXIST) {
      return 0;
    }
    return -1;
  }

  fp = fdopen(fd, "w");
  if(fp == NULL) {
    int saved_errno = errno;
    (void)close(fd);
    errno = saved_errno;
    return -1;
  }

  if(fputs(k_default_config, fp) == EOF) {
    (void)fclose(fp);
    errno = EIO;
    return -1;
  }

  if(fclose(fp) != 0) {
    return -1;
  }

  return 1;
}

static int
load_config(const char *path, app_config_t *cfg) {
  enum {
    SECTION_NONE = 0,
    SECTION_GENERAL,
    SECTION_UPSTREAM,
    SECTION_OVERRIDES,
    SECTION_EXCEPTIONS,
  } section = SECTION_NONE;
  FILE *fp;
  char line[512];
  size_t line_no = 0;
  bool replace_upstreams = false;

  config_release(cfg);
  config_set_defaults(cfg);
  config_apply_builtin_upstreams(cfg);

  /* Open the configuration itself (not a separately checked pathname).
   * Do not follow a replacement symlink or read a directory/device. */
  int fd = open(path, O_RDONLY | O_NOFOLLOW);
  struct stat config_stat;
  if(fd < 0) {
    return -1;
  }
  if(fstat(fd, &config_stat) != 0) {
    int saved_errno = errno;
    (void)close(fd);
    errno = saved_errno;
    return -1;
  }
  if(!S_ISREG(config_stat.st_mode)) {
    (void)close(fd);
    errno = EINVAL;
    return -1;
  }
  if(config_stat.st_size < 0 ||
     (uintmax_t)config_stat.st_size > MAX_CONFIG_FILE_BYTES) {
    (void)close(fd);
    errno = EFBIG;
    return -1;
  }
  fp = fdopen(fd, "r");
  if(fp == NULL) {
    int saved_errno = errno;
    (void)close(fd);
    errno = saved_errno;
    return -1;
  }

  cfg->rule_count = 0;
  cfg->exception_count = 0;

  while(fgets(line, sizeof(line), fp) != NULL) {
    char *s;
    char *eq;
    char *key;
    char *value;
    struct in_addr addr;

    ++line_no;

    /* Reject truncated lines instead of accepting a shortened block mask. */
    size_t line_length = strlen(line);
    if(line_length == sizeof(line) - 1 && line[line_length - 1] != '\n') {
      fclose(fp);
      return -1;
    }

    s = trim(line);

    if(*s == '\0' || *s == '#' || *s == ';') {
      continue;
    }

    if(*s == '[') {
      char *end = strchr(s, ']');
      if(end == NULL) {
        continue;
      }

      *end = '\0';
      s = trim(s + 1);

      if(!strcasecmp(s, "general") || !strcasecmp(s, "settings")) {
        section = SECTION_GENERAL;
      } else if(!strcasecmp(s, "upstream") || !strcasecmp(s, "upstreams")) {
        section = SECTION_UPSTREAM;
      } else if(!strcasecmp(s, "override") || !strcasecmp(s, "overrides")) {
        section = SECTION_OVERRIDES;
      } else if(!strcasecmp(s, "exception") || !strcasecmp(s, "exceptions")) {
        section = SECTION_EXCEPTIONS;
      } else {
        section = SECTION_NONE;
      }

      continue;
    }

    strip_inline_comment(s);
    if(*s == '\0') {
      continue;
    }

    if(section == SECTION_EXCEPTIONS) {
      eq = strchr(s, '=');
      if(eq != NULL) {
        *eq = '\0';
      }

      key = trim(s);
      if(*key != '\0') {
        int rc = config_add_exception(cfg, key);
        if(rc == -3) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu exception mask too long, ignoring '%s'\n",
                             path, line_no, key);
        } else if(rc == -4 || rc == -5) {
          (void)fclose(fp);
          errno = rc == -5 ? E2BIG : ENOMEM;
          return -1;
        }
      }
      continue;
    }

    eq = strchr(s, '=');
    if(eq == NULL) {
      continue;
    }

    *eq = '\0';
    key = trim(s);
    value = trim(eq + 1);

    if(*key == '\0' || *value == '\0') {
      continue;
    }

    if(section == SECTION_GENERAL ||
       (section == SECTION_NONE &&
        (!strcasecmp(key, "log") || !strcasecmp(key, "debug") ||
         !strcasecmp(key, "quiet") || !strcasecmp(key, "bind") ||
         !strcasecmp(key, "bind6")))) {
      if(!strcasecmp(key, "log")) {
        snprintf(cfg->log_path, sizeof(cfg->log_path), "%s", value);
      } else if(!strcasecmp(key, "debug")) {
        int parsed_debug;

        if(parse_int_strict(value, &parsed_debug) == 0) {
          cfg->debug_enabled = parsed_debug != 0 ? 1 : 0;
        } else {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid debug value '%s', keeping %s\n",
                             path, line_no, value,
                             cfg->debug_enabled ? "enabled" : "disabled");
        }
      } else if(!strcasecmp(key, "quiet")) {
        int parsed_quiet;

        if(parse_int_strict(value, &parsed_quiet) == 0) {
          cfg->quiet_enabled = parsed_quiet != 0 ? 1 : 0;
        } else {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid quiet value '%s', keeping %s\n",
                             path, line_no, value,
                             cfg->quiet_enabled ? "enabled" : "disabled");
        }
      } else if(!strcasecmp(key, "bind")) {
        if(config_set_bind_address(cfg, value) != 0) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid bind address '%s', keeping %s\n",
                             path, line_no, value, cfg->bind_text);
        }
      } else if(!strcasecmp(key, "bind6")) {
        if(config_value_is_disabled(value)) {
          config_disable_bind6_address(cfg);
        } else if(config_set_bind6_address(cfg, value) != 0) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid bind6 address '%s', keeping %s\n",
                             path, line_no, value, cfg->bind6_text);
        }
      }
    } else if(section == SECTION_UPSTREAM) {
      if(!strcasecmp(key, "server") || !strcasecmp(key, "dns")) {
        if(!replace_upstreams) {
          cfg->upstream_count = 0;
          replace_upstreams = true;
        }

        if(inet_pton(AF_INET, value, &addr) != 1) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid upstream server '%s', ignoring\n",
                             path, line_no, value);
        } else if(config_add_upstream(cfg, value) != 0) {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu too many upstream servers, ignoring '%s'\n",
                             path, line_no, value);
        }
      } else if(!strcasecmp(key, "timeout_ms")) {
        int parsed_timeout;

        if(parse_int_strict(value, &parsed_timeout) == 0 &&
            parsed_timeout > 0) {
          cfg->timeout_ms = parsed_timeout;
        } else {
          config_add_warning(cfg,
                             "[nanodns] warning: %s:%zu invalid timeout_ms '%s', using %d\n",
                             path, line_no, value, DEFAULT_TIMEOUT_MS);
          cfg->timeout_ms = DEFAULT_TIMEOUT_MS;
        }
      }
    } else if(section == SECTION_OVERRIDES) {
      int rc = config_add_rule(cfg, key, value);
      if(rc == -2) {
        config_add_warning(cfg,
                           "[nanodns] warning: %s:%zu invalid override IPv4 '%s' for mask '%s', ignoring\n",
                           path, line_no, value, key);
      } else if(rc == -3) {
        config_add_warning(cfg,
                           "[nanodns] warning: %s:%zu override mask too long, ignoring '%s'\n",
                           path, line_no, key);
      } else if(rc == -4 || rc == -5) {
        (void)fclose(fp);
        errno = rc == -5 ? E2BIG : ENOMEM;
        return -1;
      }
    }
  }

  if(ferror(fp)) {
    fclose(fp);
    return -1;
  }
  if(fclose(fp) != 0) {
    return -1;
  }

  if(cfg->upstream_count == 0) {
    config_apply_builtin_upstreams(cfg);
  }

  return 0;
}

static void
print_banner(void) {
  log_printf("============================================================\n");
  log_printf("%s v%s\n", APP_NAME, APP_VERSION);
  log_printf("Build: %s %s\n", __DATE__, __TIME__);
  log_printf("%s\n", APP_COPYRIGHT);
  log_printf("============================================================\n");
}

static int
send_startup_notification(const app_config_t *cfg, bool ipv4_listening,
                          bool ipv6_listening) {
  notify_request_t req;
  int rc;

  memset(&req, 0, sizeof(req));
  if(ipv4_listening && ipv6_listening) {
    rc = snprintf(req.message, sizeof(req.message),
                  "%s v%s %s\nListening on %s:%d and [%s]:%d", APP_NAME,
                  APP_VERSION, APP_COPYRIGHT, cfg->bind_text, DNS_PORT,
                  cfg->bind6_text, DNS_PORT);
  } else if(ipv6_listening) {
    rc = snprintf(req.message, sizeof(req.message),
                  "%s v%s %s\nListening on [%s]:%d", APP_NAME, APP_VERSION,
                  APP_COPYRIGHT, cfg->bind6_text, DNS_PORT);
  } else if(ipv4_listening) {
    rc = snprintf(req.message, sizeof(req.message),
                  "%s v%s %s\nListening on %s:%d", APP_NAME, APP_VERSION,
                  APP_COPYRIGHT, cfg->bind_text, DNS_PORT);
  } else {
    rc = snprintf(req.message, sizeof(req.message),
                  "%s v%s %s\nNo DNS listener active", APP_NAME, APP_VERSION,
                  APP_COPYRIGHT);
  }
  if(rc < 0 || (size_t)rc >= sizeof(req.message)) {
    log_printf("[nanodns] failed to build startup notification message\n");
    return -1;
  }

  rc = sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
  if(rc != 0) {
    log_printf("[nanodns] sceKernelSendNotificationRequest failed: %d\n", rc);
    return -1;
  }

  return 0;
}

static int
elevate_privileges(void) {
  pid_t pid = getpid();

#if defined(PLATFORM_PS4)
  (void)pid;
  return 0;
#else
  if(kernel_set_ucred_authid(pid, PRIVILEGED_AUTHID) != 0) {
    log_printf("[nanodns] unable to change AuthID for pid %d\n", pid);
    return -1;
  }

  log_printf("[nanodns] AuthID updated for pid %d\n", pid);
  return 0;
#endif
}

static int64_t
now_ms(void) {
  /* Wall-clock adjustments during rest/resume must not extend DNS timeouts. */
#ifdef CLOCK_MONOTONIC
  struct timespec ts;
  if(clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
  }
#endif
  struct timeval tv;
  if(gettimeofday(&tv, NULL) != 0) {
    return 0;
  }
  return (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static int
dns_expand_name(const uint8_t *packet, size_t packet_len, size_t *offset,
                char *output, size_t output_len) {
  size_t cursor = *offset;
  size_t end_offset = (size_t)-1;
  size_t out = 0;
  int jumps = 0;

  if(output_len == 0) {
    return -1;
  }

  while(cursor < packet_len) {
    uint8_t len = packet[cursor];

    if((len & 0xc0) == 0xc0) {
      uint16_t ptr;

      if(cursor + 1 >= packet_len) {
        return -1;
      }

      ptr = (uint16_t)(((len & 0x3f) << 8) | packet[cursor + 1]);
      if(ptr >= packet_len || ++jumps > 16) {
        return -1;
      }

      if(end_offset == (size_t)-1) {
        end_offset = cursor + 2;
      }

      cursor = ptr;
      continue;
    }

    if((len & 0xc0) != 0) {
      return -1;
    }

    ++cursor;
    if(len == 0) {
      output[out] = '\0';
      *offset = end_offset == (size_t)-1 ? cursor : end_offset;
      return 0;
    }

    if(cursor + len > packet_len) {
      return -1;
    }

    if(out != 0) {
      if(out + 1 >= output_len) {
        return -1;
      }
      output[out++] = '.';
    }

    if(out + len >= output_len) {
      return -1;
    }

    memcpy(&output[out], &packet[cursor], len);
    out += len;
    cursor += len;
  }

  return -1;
}

static int
dns_parse_question(const uint8_t *packet, size_t packet_len, dns_question_t *q) {
  size_t offset = 12;
  char normalized[MAX_DOMAIN_LEN];

  if(packet_len < 12) {
    return -1;
  }

  memset(q, 0, sizeof(*q));
  q->id = read_u16(&packet[0]);
  q->flags = read_u16(&packet[2]);
  q->qdcount = read_u16(&packet[4]);
  q->ancount = read_u16(&packet[6]);
  q->nscount = read_u16(&packet[8]);
  q->arcount = read_u16(&packet[10]);
  q->qname_offset = offset;

  if(q->qdcount == 0) {
    return -1;
  }

  if(dns_expand_name(packet, packet_len, &offset, q->qname, sizeof(q->qname)) !=
     0) {
    return -1;
  }

  if(offset + 4 > packet_len) {
    return -1;
  }

  q->qtype = read_u16(&packet[offset]);
  q->qclass = read_u16(&packet[offset + 2]);
  q->question_end = offset + 4;

  normalize_domain(q->qname, normalized, sizeof(normalized));
  snprintf(q->qname, sizeof(q->qname), "%s", normalized);

  return 0;
}

/* Native wildcard matching is in dns_mask.h for host-side regression tests. */
static int
protected_domain_match(const char *domain) {
  for(size_t i = 0; i < PROTECTED_RULE_COUNT; ++i) {
    if(domain_mask_match(k_protected_masks[i], domain)) {
      return 1;
    }
  }
  return 0;
}

/* Reject protected hostnames hidden in a resolver's answer section.
 * Malformed answer records are refused, not passed to the client. */
static int
dns_response_has_blocked_target(const uint8_t *packet, size_t packet_len,
                                const dns_question_t *question) {
  size_t cursor = question->question_end;
  for(size_t i = 0; i < question->ancount; ++i) {
    char owner[MAX_DOMAIN_LEN], target[MAX_DOMAIN_LEN];
    uint16_t type, rdlength;
    size_t rdata_start, name_cursor;

    if(dns_expand_name(packet, packet_len, &cursor, owner,
                       sizeof(owner)) != 0 || cursor + 10 > packet_len) {
      return 1;
    }
    normalize_domain(owner, owner, sizeof(owner));
    if(protected_domain_match(owner)) return 1;
    type = read_u16(packet + cursor);
    rdlength = read_u16(packet + cursor + 8);
    cursor += 10;
    rdata_start = cursor;
    if((size_t)rdlength > packet_len - cursor) return 1;

    name_cursor = rdata_start;
    if(type == 15 || type == 64 || type == 65) {
      if(rdlength < 3) return 1;
      name_cursor += 2;
    } else if(type == 33) {
      if(rdlength < 7) return 1;
      name_cursor += 6;
    }

    if(type == 2 || type == 5 || type == 12 || type == 15 ||
       type == 33 || type == 39 || type == 64 || type == 65) {
      if(dns_expand_name(packet, packet_len, &name_cursor, target,
                         sizeof(target)) != 0 ||
         name_cursor > rdata_start + rdlength) return 1;
      normalize_domain(target, target, sizeof(target));
      if(protected_domain_match(target)) return 1;
    }

    cursor = rdata_start + rdlength;
  }
  return 0;
}

static const override_rule_t *
find_matching_rule(const app_config_t *cfg, const char *domain) {
  for(size_t i = 0; i < cfg->rule_count; ++i) {
    if(domain_mask_match(cfg->rules[i].mask, domain)) {
      return &cfg->rules[i];
    }
  }

  return NULL;
}

static int
has_matching_exception(const app_config_t *cfg, const char *domain) {
  for(size_t i = 0; i < cfg->exception_count; ++i) {
    if(domain_mask_match(cfg->exceptions[i].mask, domain)) {
      return 1;
    }
  }

  return 0;
}

static int
build_error_response(const uint8_t *request, size_t request_len,
                     const dns_question_t *question, uint16_t rcode,
                     uint8_t *response, size_t response_cap,
                     size_t *response_len) {
  size_t question_len;

  if(response_cap < question->question_end) {
    return -1;
  }

  question_len = question->question_end - 12;
  memcpy(response, request, question->question_end);
  write_u16(&response[2],
            (uint16_t)(0x8000 | (question->flags & 0x0100) | 0x0080 |
                       (rcode & 0x000f)));
  write_u16(&response[4], 1);
  write_u16(&response[6], 0);
  write_u16(&response[8], 0);
  write_u16(&response[10], 0);
  *response_len = 12 + question_len;

  (void)request_len;
  return 0;
}

static int
build_nodata_response(const uint8_t *request, size_t request_len,
                      const dns_question_t *question, uint8_t *response,
                      size_t response_cap, size_t *response_len) {
  return build_error_response(request, request_len, question, 0, response,
                              response_cap, response_len);
}

static int
build_override_response(const uint8_t *request, const dns_question_t *question,
                        const struct in_addr *addr, uint8_t *response,
                        size_t response_cap, size_t *response_len) {
  size_t question_len = question->question_end - 12;
  size_t offset;

  if(response_cap < question->question_end + 16) {
    return -1;
  }

  memcpy(response, request, question->question_end);
  write_u16(&response[2],
            (uint16_t)(0x8000 | (question->flags & 0x0100) | 0x0080));
  write_u16(&response[4], 1);
  write_u16(&response[6], 1);
  write_u16(&response[8], 0);
  write_u16(&response[10], 0);

  offset = 12 + question_len;
  write_u16(&response[offset], 0xc00c);
  offset += 2;
  write_u16(&response[offset], 1);
  offset += 2;
  write_u16(&response[offset], 1);
  offset += 2;
  write_u32(&response[offset], OVERRIDE_TTL);
  offset += 4;
  write_u16(&response[offset], 4);
  offset += 2;
  memcpy(&response[offset], &addr->s_addr, 4);
  offset += 4;

  *response_len = offset;
  return 0;
}

static void
format_sockaddr(const struct sockaddr *addr, char *ip, size_t ip_len,
                uint16_t *port) {
  if(addr->sa_family == AF_INET) {
    const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;

    if(inet_ntop(AF_INET, &sin->sin_addr, ip, ip_len) == NULL) {
      snprintf(ip, ip_len, "<invalid>");
    }
    *port = ntohs(sin->sin_port);
  } else if(addr->sa_family == AF_INET6) {
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;

    if(inet_ntop(AF_INET6, &sin6->sin6_addr, ip, ip_len) == NULL) {
      snprintf(ip, ip_len, "<invalid>");
    }
    *port = ntohs(sin6->sin6_port);
  } else {
    snprintf(ip, ip_len, "<unknown>");
    *port = 0;
  }
}

static void
log_dns_query(const dns_question_t *question, const struct sockaddr *client) {
  char client_ip[INET6_ADDRSTRLEN];
  uint16_t client_port;

  format_sockaddr(client, client_ip, sizeof(client_ip), &client_port);

  log_printf("[nanodns] query from=%s%s%s:%u id=0x%04x qname=%s qtype=%s(%u) qclass=%u\n",
             client->sa_family == AF_INET6 ? "[" : "", client_ip,
             client->sa_family == AF_INET6 ? "]" : "", client_port,
             question->id, question->qname[0] ? question->qname : ".",
             dns_type_to_string(question->qtype), question->qtype,
             question->qclass);
}

static void
log_answer_record(const uint8_t *packet, size_t packet_len, size_t *offset,
                  size_t index) {
  char name[MAX_DOMAIN_LEN];
  char target[MAX_DOMAIN_LEN];
  uint16_t type;
  uint16_t klass;
  uint16_t rdlength;
  uint32_t ttl;
  size_t rdata_offset;
  char ipbuf[INET6_ADDRSTRLEN];

  if(dns_expand_name(packet, packet_len, offset, name, sizeof(name)) != 0) {
    log_printf("[nanodns]   answer[%zu] <invalid owner name>\n", index);
    *offset = packet_len;
    return;
  }

  if(*offset + 10 > packet_len) {
    log_printf("[nanodns]   answer[%zu] <truncated rr header>\n", index);
    *offset = packet_len;
    return;
  }

  type = read_u16(&packet[*offset]);
  klass = read_u16(&packet[*offset + 2]);
  ttl = read_u32(&packet[*offset + 4]);
  rdlength = read_u16(&packet[*offset + 8]);
  *offset += 10;

  if(*offset + rdlength > packet_len) {
    log_printf("[nanodns]   answer[%zu] <truncated rr data>\n", index);
    *offset = packet_len;
    return;
  }

  rdata_offset = *offset;

  if(type == 1 && rdlength == 4 &&
     inet_ntop(AF_INET, &packet[rdata_offset], ipbuf, sizeof(ipbuf)) != NULL) {
    log_printf("[nanodns]   answer[%zu] name=%s type=A ttl=%u class=%u data=%s\n",
               index, name[0] ? name : ".", ttl, klass, ipbuf);
  } else if(type == 28 && rdlength == 16 &&
            inet_ntop(AF_INET6, &packet[rdata_offset], ipbuf,
                      sizeof(ipbuf)) != NULL) {
    log_printf("[nanodns]   answer[%zu] name=%s type=AAAA ttl=%u class=%u data=%s\n",
               index, name[0] ? name : ".", ttl, klass, ipbuf);
  } else if((type == 2 || type == 5 || type == 12) &&
            dns_expand_name(packet, packet_len, &rdata_offset, target,
                            sizeof(target)) == 0) {
    log_printf("[nanodns]   answer[%zu] name=%s type=%s ttl=%u class=%u data=%s\n",
               index, name[0] ? name : ".", dns_type_to_string(type), ttl, klass,
               target[0] ? target : ".");
  } else {
    log_printf("[nanodns]   answer[%zu] name=%s type=%s(%u) ttl=%u class=%u rdlen=%u\n",
               index, name[0] ? name : ".", dns_type_to_string(type), type, ttl,
               klass, rdlength);
  }

  *offset += rdlength;
}

static void
log_dns_response(const uint8_t *packet, size_t packet_len, const char *via) {
  dns_question_t question;
  uint16_t flags;
  uint16_t rcode;
  size_t offset;

  if(dns_parse_question(packet, packet_len, &question) != 0) {
    log_printf("[nanodns] response via=%s <failed to parse>\n", via);
    return;
  }

  flags = read_u16(&packet[2]);
  rcode = (uint16_t)(flags & 0x000f);

  log_printf("[nanodns] response via=%s id=0x%04x qname=%s qtype=%s(%u) rcode=%s(%u) answers=%u authority=%u additional=%u\n",
             via, question.id, question.qname[0] ? question.qname : ".",
             dns_type_to_string(question.qtype), question.qtype,
             dns_rcode_to_string(rcode), rcode, read_u16(&packet[6]),
             read_u16(&packet[8]), read_u16(&packet[10]));

  offset = question.question_end;
  for(size_t i = 0; i < question.ancount && offset < packet_len; ++i) {
    log_answer_record(packet, packet_len, &offset, i);
  }
}

static int
open_upstream_socket(const upstream_t *upstream) {
  struct sockaddr_in upstream_addr;
  int fd;

  memset(&upstream_addr, 0, sizeof(upstream_addr));
  upstream_addr.sin_family = AF_INET;
  upstream_addr.sin_port = htons(DNS_PORT);
  upstream_addr.sin_addr = upstream->addr;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd < 0) {
    log_printf("[nanodns] upstream %s socket failed: %s\n", upstream->text,
               strerror(errno));
    return -1;
  }

  if(connect(fd, (struct sockaddr *)&upstream_addr, sizeof(upstream_addr)) !=
     0) {
    log_printf("[nanodns] upstream %s connect failed: %s\n", upstream->text,
               strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

static void
close_upstream_socket(int *fd) {
  if(*fd >= 0) {
    close(*fd);
    *fd = -1;
  }
}

static void
close_upstream_sockets(int *fds, size_t count) {
  for(size_t i = 0; i < count; ++i) {
    close_upstream_socket(&fds[i]);
  }
}

static void
init_server_listener(server_listener_t *listener, int family,
                     const char *name, bool retry_enabled) {
  listener->fd = -1;
  listener->family = family;
  listener->name = name;
  listener->retry_enabled = retry_enabled;
  listener->retry_at_ms = 0;
}

static void
invalidate_server_listener(server_listener_t *listener) {
  if(listener->fd >= 0) {
    close(listener->fd);
    listener->fd = -1;
  }
  listener->retry_at_ms = now_ms() + LISTENER_RETRY_MS;
}

static void
log_server_listener_addr(const app_config_t *cfg, const server_listener_t *listener,
                         const char *prefix) {
  if(listener->family == AF_INET6) {
    log_printf("[nanodns] %s [%s]:%d\n", prefix, cfg->bind6_text, DNS_PORT);
  } else {
    log_printf("[nanodns] %s %s:%d\n", prefix, cfg->bind_text, DNS_PORT);
  }
}

static int
open_server_socket4(const app_config_t *cfg) {
  struct sockaddr_in listen_addr;
  int fd;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  if(fd < 0) {
    log_errno("socket(server-ipv4)");
    return -1;
  }

  /* Exclusive UDP port ownership: never share DNS port 53 with another
   * nanoDNS instance. A duplicate load must fail instead of stealing queries. */
  memset(&listen_addr, 0, sizeof(listen_addr));
  listen_addr.sin_family = AF_INET;
  listen_addr.sin_port = htons(DNS_PORT);
  listen_addr.sin_addr = cfg->bind_addr;

  if(bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) != 0) {
    log_printf("[nanodns] bind(%s:%d) failed: %s\n", cfg->bind_text, DNS_PORT,
               strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

static int
open_server_socket6(const app_config_t *cfg) {
  struct sockaddr_in6 listen_addr;
  int fd;

  if(!cfg->bind6_enabled) {
    return -1;
  }

  fd = socket(AF_INET6, SOCK_DGRAM, 0);
  if(fd < 0) {
    log_printf("[nanodns] warning: IPv6 listener unavailable: %s\n",
               strerror(errno));
    return -1;
  }

#ifdef IPV6_V6ONLY
  int v6only = 1;
  if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) != 0) {
    log_printf("[nanodns] warning: setsockopt(IPV6_V6ONLY): %s\n",
               strerror(errno));
  }
#endif

  memset(&listen_addr, 0, sizeof(listen_addr));
  listen_addr.sin6_family = AF_INET6;
  listen_addr.sin6_port = htons(DNS_PORT);
  listen_addr.sin6_addr = cfg->bind6_addr;

  if(bind(fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) != 0) {
    log_printf("[nanodns] warning: IPv6 bind([%s]:%d) failed: %s\n",
               cfg->bind6_text, DNS_PORT, strerror(errno));
    close(fd);
    return -1;
  }

  return fd;
}

static int
open_server_listener(const app_config_t *cfg, server_listener_t *listener) {
  int fd;

  fd = listener->family == AF_INET6 ? open_server_socket6(cfg) :
                                      open_server_socket4(cfg);
  if(fd < 0) {
    if(listener->retry_enabled) {
      listener->retry_at_ms = now_ms() + LISTENER_RETRY_MS;
    }
    return -1;
  }

  listener->fd = fd;
  listener->retry_enabled = true;
  listener->retry_at_ms = 0;
  return 0;
}

static int
drain_upstream_socket(int fd) {
  uint8_t discard[MAX_DNS_PACKET];
  struct pollfd pfd;

  pfd.fd = fd;
  pfd.events = POLLIN;

  /* A continuous stream of stale packets must not stall shutdown. */
  for(size_t drained = 0; drained < 64 && g_running; ++drained) {
    ssize_t nread;

    pfd.revents = 0;
    if(poll(&pfd, 1, 0) <= 0) {
      return 0;
    }

    if((pfd.revents & POLLIN) == 0) {
      return (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) == 0 ? 0 : -1;
    }

    nread = recv(fd, discard, sizeof(discard), 0);
    if(nread <= 0) {
      return -1;
    }
  }
  return g_running ? 0 : -1;
}

static int
server_socket_needs_reopen(int err) {
  switch(err) {
  case EBADF:
  case EINVAL:
  case ENOTSOCK:
    return 1;
  default:
    return 0;
  }
}

static int
forward_query_to_upstream(const app_config_t *cfg, const uint8_t *request,
                          size_t request_len, const dns_question_t *question,
                          int *upstream_fds,
                          uint8_t *response, size_t response_cap,
                          size_t *response_len, char *via, size_t via_len) {
  /* Give each configured resolver its own bounded reply window. A silent
   * primary must not consume the entire backup resolver's budget. */
  for(size_t i = 0; i < cfg->upstream_count && g_running; ++i) {
    int64_t deadline_ms;
    struct pollfd pfd;
    int fd;
    int poll_rc;

    fd = upstream_fds[i];
    if(fd < 0) {
      fd = open_upstream_socket(&cfg->upstreams[i]);
      if(fd < 0) {
        continue;
      }

      upstream_fds[i] = fd;
    }

    if(drain_upstream_socket(fd) != 0) {
      if(!g_running) {
        return -1;
      }
      log_printf("[nanodns] upstream %s drain failed, reconnecting\n",
                 cfg->upstreams[i].text);
      close_upstream_socket(&upstream_fds[i]);
      fd = open_upstream_socket(&cfg->upstreams[i]);
      if(fd < 0) {
        continue;
      }

      upstream_fds[i] = fd;
    }

    if(!g_running) {
      return -1;
    }
    if(send(fd, request, request_len, 0) < 0) {
      log_printf("[nanodns] upstream %s send failed: %s\n",
                 cfg->upstreams[i].text, strerror(errno));
      close_upstream_socket(&upstream_fds[i]);
      continue;
    }

    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    deadline_ms = now_ms() + cfg->timeout_ms;

    while(g_running) {
      int64_t timeout_ms = deadline_ms - now_ms();

      if(timeout_ms <= 0) {
        log_printf("[nanodns] upstream %s timed out\n", cfg->upstreams[i].text);
        close_upstream_socket(&upstream_fds[i]);
        break;
      }

      poll_rc = poll(&pfd, 1, (int)timeout_ms);
      if(poll_rc == 0) {
        log_printf("[nanodns] upstream %s timed out\n",
                   cfg->upstreams[i].text);
        close_upstream_socket(&upstream_fds[i]);
        break;
      }

      if(poll_rc < 0) {
        if(errno == EINTR) {
          if(!g_running) {
            return -1;
          }
          continue;
        }

        log_printf("[nanodns] upstream %s poll failed: %s\n",
                   cfg->upstreams[i].text, strerror(errno));
        close_upstream_socket(&upstream_fds[i]);
        break;
      }

      if((pfd.revents & POLLIN) != 0) {
        ssize_t nread = recv(fd, response, response_cap, 0);
        if(nread < 0) {
          log_printf("[nanodns] upstream %s recv failed: %s\n",
                     cfg->upstreams[i].text, strerror(errno));
          close_upstream_socket(&upstream_fds[i]);
          break;
        } else if((size_t)nread < 12) {
          log_printf("[nanodns] upstream %s returned short packet (%zd bytes)\n",
                     cfg->upstreams[i].text, nread);
          close_upstream_socket(&upstream_fds[i]);
          break;
        } else {
          dns_question_t reply_question;
          if(read_u16(response) != question->id ||
             dns_parse_question(response, (size_t)nread, &reply_question) != 0 ||
             (reply_question.flags & 0x8000) == 0 ||
             (reply_question.flags & 0x7800) != 0 ||
             reply_question.qdcount != 1 ||
             reply_question.qtype != question->qtype ||
             reply_question.qclass != question->qclass ||
             strcmp(reply_question.qname, question->qname) != 0) {
            log_printf("[nanodns] upstream %s returned unrelated DNS response\n",
                       cfg->upstreams[i].text);
            close_upstream_socket(&upstream_fds[i]);
            break;
          }
          if(dns_response_has_blocked_target(response, (size_t)nread,
                                             &reply_question)) {
            log_printf("[nanodns] upstream %s returned protected alias; refusing\n",
                       cfg->upstreams[i].text);
            close_upstream_socket(&upstream_fds[i]);
            break;
          }
          /* SERVFAIL and REFUSED are resolver failures; try the next
           * configured upstream. NXDOMAIN and NODATA are valid answers. */
          if((reply_question.flags & 0x000f) == 2 ||
             (reply_question.flags & 0x000f) == 5) {
            log_printf("[nanodns] upstream %s returned failure rcode=%u; trying next\n",
                       cfg->upstreams[i].text,
                       (unsigned)(reply_question.flags & 0x000f));
            close_upstream_socket(&upstream_fds[i]);
            break;
          }
          *response_len = (size_t)nread;
          snprintf(via, via_len, "%s", cfg->upstreams[i].text);
          return 0;
        }
      } else if((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
        log_printf("[nanodns] upstream %s poll events=0x%x\n",
                   cfg->upstreams[i].text, pfd.revents);
        close_upstream_socket(&upstream_fds[i]);
        break;
      }

      pfd.revents = 0;
    }
  }

  return -1;
}

static void
send_dns_response_to_client(int server_fd, const uint8_t *response,
                            size_t response_len,
                            const struct sockaddr *client_addr,
                            socklen_t client_len, const char *via,
                            const char *error_context) {
  if(sendto(server_fd, response, response_len, 0, client_addr, client_len) <
     0) {
    log_errno(error_context);
  } else {
    log_dns_response(response, response_len, via);
  }
}

static void
handle_dns_request(const app_config_t *cfg, int server_fd, int *upstream_fds,
                   uint8_t *request, size_t request_len,
                   const struct sockaddr *client_addr, socklen_t client_len) {
  uint8_t response[MAX_DNS_PACKET];
  dns_question_t question;
  size_t response_len = 0;

  if(dns_parse_question(request, request_len, &question) != 0) {
    log_printf("[nanodns] received malformed DNS packet (%zu bytes)\n",
               request_len);
    return;
  }

  log_dns_query(&question, client_addr);

  /* One class-IN question is all this resolver understands. Never relay
   * additional/unsupported questions without evaluating the denylist. */
  if(question.qdcount != 1 || question.qclass != 1 ||
     (question.flags & 0xF800) != 0) {
    uint16_t rcode = question.qdcount != 1 || (question.flags & 0xF800) != 0
                         ? 1 : 5;
    if(build_error_response(request, request_len, &question, rcode, response,
                            sizeof(response), &response_len) == 0) {
      send_dns_response_to_client(server_fd, response, response_len,
                                  client_addr, client_len, "unsupported-query",
                                  "sendto(client, unsupported-query)");
    }
    return;
  }

  {
    const override_rule_t *rule = NULL;
    override_rule_t mandatory_deny_rule;

    if(protected_domain_match(question.qname)) {
      memset(&mandatory_deny_rule, 0, sizeof(mandatory_deny_rule));
      snprintf(mandatory_deny_rule.mask, sizeof(mandatory_deny_rule.mask),
               "%s", "mandatory-console-blocklist");
      snprintf(mandatory_deny_rule.text, sizeof(mandatory_deny_rule.text),
               "%s", "0.0.0.0");
      rule = &mandatory_deny_rule;
    } else if(has_matching_exception(cfg, question.qname)) {
      log_printf("[nanodns] exception matched for unprotected %s\n",
                 question.qname);
    } else {
      rule = find_matching_rule(cfg, question.qname);
    }

    if(rule != NULL) {
      int build_rc;
      const char *response_via;

      log_printf("[nanodns] override matched %s -> %s for %s\n", rule->mask,
                 rule->text, question.qname);

      if(question.qtype == 1 || question.qtype == 255) {
        build_rc = build_override_response(request, &question, &rule->addr,
                                           response, sizeof(response),
                                           &response_len);
        response_via = "override";
      } else {
        build_rc = build_nodata_response(request, request_len, &question,
                                         response, sizeof(response),
                                         &response_len);
        response_via = "override-nodata";
      }

      if(build_rc == 0) {
        send_dns_response_to_client(
            server_fd, response, response_len, client_addr, client_len,
            response_via, "sendto(client, override-local)");
        return;
      }

      if(build_error_response(request, request_len, &question, 2, response,
                              sizeof(response), &response_len) == 0) {
        send_dns_response_to_client(
            server_fd, response, response_len, client_addr, client_len,
            "override-servfail", "sendto(client, override-servfail)");
        return;
      }

      log_printf("[nanodns] blocked response construction failed; dropping %s without upstream\n",
                 question.qname);
      return;
    }
  }

  {
    char via[INET_ADDRSTRLEN];

    if(forward_query_to_upstream(cfg, request, request_len, &question,
                                 upstream_fds, response, sizeof(response),
                                 &response_len, via, sizeof(via)) == 0) {
      send_dns_response_to_client(server_fd, response, response_len,
                                  client_addr, client_len, via,
                                  "sendto(client, upstream)");
      return;
    }
  }

  if(!g_running) {
    return;
  }
  log_printf("[nanodns] all upstreams failed for %s\n", question.qname);
  if(build_error_response(request, request_len, &question, 2, response,
                          sizeof(response), &response_len) == 0) {
    send_dns_response_to_client(server_fd, response, response_len, client_addr,
                                client_len, "local-servfail",
                                "sendto(client, servfail)");
  }
}

static void
handle_server_listener_event(const app_config_t *cfg,
                             server_listener_t *listener, int *upstream_fds,
                             short revents) {
  uint8_t request[MAX_DNS_PACKET];
  struct sockaddr_storage client_addr;
  socklen_t client_len = sizeof(client_addr);
  ssize_t received;

  if((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
    log_printf("[nanodns] %s listening socket poll events=0x%x, recreating\n",
               listener->name, revents);
    invalidate_server_listener(listener);
    return;
  }

  if((revents & POLLIN) == 0) {
    return;
  }

  memset(&client_addr, 0, sizeof(client_addr));
  received = recvfrom(listener->fd, request, sizeof(request), 0,
                      (struct sockaddr *)&client_addr, &client_len);
  if(received < 0) {
    if(errno == EINTR || errno == EAGAIN) {
      return;
    }

    log_errno("recvfrom(client)");
    if(server_socket_needs_reopen(errno)) {
      invalidate_server_listener(listener);
    }
    return;
  }

  handle_dns_request(cfg, listener->fd, upstream_fds, request, (size_t)received,
                     (const struct sockaddr *)&client_addr, client_len);
}

static int
net_init(void) {
  if(sceNetInit() != 0) {
    errno = EIO;
    log_errno("sceNetInit");
    return -1;
  }

  g_libnet_mem_id = sceNetPoolCreate("nanodns", 64 * 1024, 0);
  if(g_libnet_mem_id < 0) {
    errno = EIO;
    log_errno("sceNetPoolCreate");
    if(sceNetTerm() != 0) {
      errno = EIO;
      log_errno("sceNetTerm");
    }
    return -1;
  }

  return 0;
}

static void
net_fini(void) {
  if(g_libnet_mem_id >= 0) {
    if(sceNetPoolDestroy(g_libnet_mem_id) != 0) {
      errno = EIO;
      log_errno("sceNetPoolDestroy");
    }
    g_libnet_mem_id = -1;
  }

  if(sceNetTerm() != 0) {
    errno = EIO;
    log_errno("sceNetTerm");
  }
}

static void
on_signal(int signo) {
  (void)signo;
  g_running = 0;
}

int
main(void) {
  app_config_t cfg = {0};
  int upstream_fds[MAX_UPSTREAMS];
  server_listener_t listeners[SERVER_LISTENER_COUNT];
  struct pollfd pfds[SERVER_LISTENER_COUNT];
  size_t poll_listener_index[SERVER_LISTENER_COUNT];
  int config_state;
  int config_errno = 0;
  int config_loaded = 0;
  int data_dir_state;
  int data_dir_errno = 0;

  for(size_t i = 0; i < MAX_UPSTREAMS; ++i) {
    upstream_fds[i] = -1;
  }

  init_server_listener(&listeners[SERVER_LISTENER_IPV4], AF_INET, "IPv4",
                       true);
  init_server_listener(&listeners[SERVER_LISTENER_IPV6], AF_INET6, "IPv6",
                       false);

#if defined(PLATFORM_PS5)
  /* Distinguish the resident thread from the original payload. The ELF
   * path remains unchanged for local installation/upgrade compatibility. */
  errno = 0;
  long process_label_rc = syscall(SYS_thr_set_name, -1, PAYLOAD_PROCESS_LABEL);
  int process_label_errno = process_label_rc == 0 ? 0 : errno;
#endif
  signal(SIGINT, on_signal);
  signal(SIGTERM, on_signal);

  data_dir_state = ensure_runtime_dir_exists(DATA_DIR);
  if(data_dir_state < 0) {
    data_dir_errno = errno;
  }

  config_state = ensure_default_config_exists(CONFIG_PATH);
  if(config_state < 0) {
    config_errno = errno;
  }

  if(load_config(CONFIG_PATH, &cfg) != 0) {
    config_release(&cfg);
    config_set_defaults(&cfg);
    config_apply_builtin_upstreams(&cfg);
    (void)config_apply_builtin_overrides(&cfg);
  } else {
    config_loaded = 1;
  }

  (void)logger_init(&cfg);
  print_banner();
#if defined(PLATFORM_PS5)
  log_printf("[nanodns] process-label=%s thread-name-rc=%ld errno=%d pid=%ld\n",
             PAYLOAD_PROCESS_LABEL, process_label_rc, process_label_errno,
             (long)getpid());
#endif

  for(size_t i = 0; i < cfg.warning_count; ++i) {
    log_printf("%s", cfg.warnings[i].text);
  }

  if(data_dir_state == 1) {
    log_printf("[nanodns] created runtime directory %s\n", DATA_DIR);
  } else if(data_dir_state < 0) {
    log_printf("[nanodns] could not create %s: %s\n", DATA_DIR,
               strerror(data_dir_errno));
  }

  if(config_state == 1) {
    log_printf("[nanodns] created default config at %s\n", CONFIG_PATH);
  } else if(config_state < 0) {
    log_printf("[nanodns] could not create %s: %s\n", CONFIG_PATH,
               strerror(config_errno));
  }

  if(!config_loaded) {
    log_printf("[nanodns] could not fully load %s, using fallback defaults\n",
               CONFIG_PATH);
  }

  if(g_log_file != NULL) {
    log_printf("[nanodns] log file: %s\n", cfg.log_path);
  }
  log_printf("[nanodns] debug output: %s\n",
             cfg.debug_enabled ? "enabled" : "disabled");
  log_printf("[nanodns] quiet mode: %s\n",
             cfg.quiet_enabled ? "enabled" : "disabled");
  log_printf("[nanodns] bind IPv4: %s:%d\n", cfg.bind_text, DNS_PORT);
  if(cfg.bind6_enabled) {
    log_printf("[nanodns] bind IPv6: [%s]:%d\n", cfg.bind6_text, DNS_PORT);
  } else {
    log_printf("[nanodns] bind IPv6: disabled\n");
  }
  log_printf("[nanodns] config loaded: %zu upstream(s), %zu rule(s), %zu exception(s), timeout=%dms\n",
             cfg.upstream_count, cfg.rule_count, cfg.exception_count,
             cfg.timeout_ms);

  for(size_t i = 0; i < cfg.upstream_count; ++i) {
    log_printf("[nanodns] upstream[%zu] = %s\n", i, cfg.upstreams[i].text);
  }

  for(size_t i = 0; i < cfg.rule_count; ++i) {
    log_printf("[nanodns] rule[%zu] = %s -> %s\n", i, cfg.rules[i].mask,
               cfg.rules[i].text);
  }

  for(size_t i = 0; i < cfg.exception_count; ++i) {
    log_printf("[nanodns] exception[%zu] = %s\n", i, cfg.exceptions[i].mask);
  }

  /* Never SIGKILL existing instances: bypassing their socket/NetPool
   * cleanup can leave the platform in an inconsistent shutdown state.
   * A second instance will fail to bind the already occupied DNS port. */
  if(elevate_privileges() != 0) {
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    logger_fini();
    config_release(&cfg);
    return EXIT_FAILURE;
  }

  if(net_init() != 0) {
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    logger_fini();
    config_release(&cfg);
    return 1;
  }

  for(size_t i = 0; i < SERVER_LISTENER_COUNT; ++i) {
    (void)open_server_listener(&cfg, &listeners[i]);
  }

  /* IPv6 alone does not protect an IPv4-configured console.  Most
   * importantly, never run half-active beside an old IPv4 nanoDNS. */
  if(listeners[SERVER_LISTENER_IPV4].fd < 0) {
    log_printf("[nanodns] startup aborted: IPv4 DNS port unavailable "
               "(duplicate payload or invalid bind address)\n");
    for(size_t i = 0; i < SERVER_LISTENER_COUNT; ++i) {
      invalidate_server_listener(&listeners[i]);
    }
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    net_fini();
    logger_fini();
    config_release(&cfg);
    return EXIT_FAILURE;
  }

  for(size_t i = 0; i < SERVER_LISTENER_COUNT; ++i) {
    if(listeners[i].fd >= 0) {
      log_server_listener_addr(&cfg, &listeners[i], "listening on");
    }
  }
  if(!cfg.bind6_enabled) {
    log_printf("[nanodns] IPv6 listener disabled by config\n");
  } else if(listeners[SERVER_LISTENER_IPV6].fd < 0) {
    log_printf("[nanodns] continuing without IPv6 listener\n");
  }

  if(!cfg.quiet_enabled) {
    (void)send_startup_notification(
        &cfg, listeners[SERVER_LISTENER_IPV4].fd >= 0,
        listeners[SERVER_LISTENER_IPV6].fd >= 0);
  }

  while(g_running) {
    nfds_t poll_count = 0;
    int64_t current_ms = now_ms();
    int poll_rc;

    for(size_t i = 0; i < SERVER_LISTENER_COUNT; ++i) {
      if(listeners[i].fd < 0 && listeners[i].retry_enabled &&
         current_ms >= listeners[i].retry_at_ms) {
        log_server_listener_addr(&cfg, &listeners[i],
                                 "attempting to restore listening socket on");
        if(open_server_listener(&cfg, &listeners[i]) == 0) {
          log_server_listener_addr(&cfg, &listeners[i],
                                   "listening socket restored on");
        }
      }
    }

    if(listeners[SERVER_LISTENER_IPV4].fd < 0 &&
       listeners[SERVER_LISTENER_IPV6].fd < 0) {
      sleep(1);
      continue;
    }

    for(size_t i = 0; i < SERVER_LISTENER_COUNT; ++i) {
      if(listeners[i].fd < 0) {
        continue;
      }

      poll_listener_index[poll_count] = i;
      pfds[poll_count].fd = listeners[i].fd;
      pfds[poll_count].events = POLLIN;
      pfds[poll_count].revents = 0;
      ++poll_count;
    }

    poll_rc = poll(pfds, poll_count, 1000);
    if(poll_rc == 0) {
      continue;
    }

    if(poll_rc < 0) {
      if(errno == EINTR) {
        continue;
      }

      log_errno("poll(server)");
      if(server_socket_needs_reopen(errno)) {
        for(size_t i = 0; i < SERVER_LISTENER_COUNT; ++i) {
          invalidate_server_listener(&listeners[i]);
        }
      }
      continue;
    }

    for(nfds_t i = 0; i < poll_count && g_running; ++i) {
      handle_server_listener_event(&cfg, &listeners[poll_listener_index[i]],
                                   upstream_fds, pfds[i].revents);
    }
  }

  log_printf("[nanodns] shutdown: closing local listeners\n");
  for(size_t i = 0; i < SERVER_LISTENER_COUNT; ++i) {
    invalidate_server_listener(&listeners[i]);
  }
  log_printf("[nanodns] shutdown: closing upstream sockets\n");
  close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
  log_printf("[nanodns] shutdown: releasing SceNet pool\n");
  net_fini();
  log_printf("[nanodns] shutdown: complete\n");
  logger_fini();
  config_release(&cfg);
  return 0;
}
