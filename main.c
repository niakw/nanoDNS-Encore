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
#define APP_VERSION "0.4-13.60.4-dev"
#define APP_COPYRIGHT "(c) Drakmor"
#define DATA_DIR "/data/nanodns"
#define CONFIG_PATH DATA_DIR "/nanodns4096.ini"
#define LEGACY_CONFIG_PATH DATA_DIR "/nanodns.ini"
#define INSTANCE_LOCK_PATH DATA_DIR "/resident.lock"
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
    "# Rules derived from: https://github.com/niakw/nanodns-console-blocklist\n"
    "# Resolver customization: Control D unfiltered, AdGuard non-filtering fallback\n"
    "# nanoDNS original by Drakmor: https://github.com/drakmor/nanoDNS\n"
    "# nanoDNS Console Blocklist — extended multi-platform publisher profile\n"
    "# Updated: 2026-11-27 | Base configuration previously tested on PS5 13.60; expanded profile unqualified.\n"
    "# Community-maintained best-effort DNS filtering; NOT a firewall.\n"
    "# Installed path: /data/nanodns/nanodns4096.ini\n"
    "# Default profile for 0.4-13.60.4 development candidates; NOT HARDWARE-QUALIFIED.\n"
    "# 1719 overrides; source capacity 4096; not compatible with the published 128-entry ELF.\n"
    "# Broad publisher inventory; candidate domains, not a verified endpoint census.\n"
    "# WARNING: brand-wide masks and the Akamai exact alias may cause collateral blocking.\n"
    "# DNS traffic bypass, direct IP traffic and pre-payload traffic are OUT OF SCOPE.\n"
    "[general]\n"
    "log=/data/nanodns/nanodns.log\n"
    "debug=0\n"
    "quiet=0\n"
    "bind=127.0.0.1\n"
    "bind6=::1\n"
    "\n"
    "[upstream]\n"
    "# Four ordered addresses, two providers; no added threat/ad filtering.\n"
    "# timeout_ms applies per upstream attempt.\n"
    "server=76.76.2.0\n"
    "server=76.76.10.0\n"
    "server=94.140.14.140\n"
    "server=94.140.14.141\n"
    "timeout_ms=1500\n"
    "\n"
    "[overrides]\n"
    "# Extended 1719-rule multi-platform profile; 124 canonical rules preserved in order.\n"
    "# Source target: 4096 overrides and 4096 exceptions; host/console results are separate.\n"
    "# Publisher discovery: https://platprices.com/publishers/\n"
    "# https://psdeals.net/au-store/publishers?additional_stores=0&platforms=ps5\n"
    "# Network reference: https://help.steampowered.com/en/faqs/view/2ea8-4d75-da21-31eb\n"
    "# https://help.playvs.com/en/articles/4919231-hardware-network-specifications-inclusion-lists\n"
    "# https://www.netify.ai/resources/applications/riot-games\n"
    "# New roots are best-effort candidates; ownership, live DNS and actual game traffic not exhaustively verified.\n"
    "# Broad blocking may disable multiplayer, account access, downloads, game content and shared services.\n"
    "# Do not use as a WAN firewall or a guarantee against network traffic.\n"
    "# Base: nanodns.ini from this repository (left untouched).\n"
    "# Legacy additions: ProsperoEden-Encore headless/network-hosts.txt @ 2122553f6274730687abee227ffd6e2ebc6f9747.\n"
    "# Runtime storage is dynamic, bounded by per-list count and INI size.\n"
    "\n"
    "# Current nanoDNS-Encore policy (124 rules)\n"
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
    "a192.d.akamai.net=0.0.0.0\n"
    "psn.akadns99.net=0.0.0.0\n"
    "*.psn.akadns99.net=0.0.0.0\n"
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
    "*nintendo*=0.0.0.0\n"
    "*nintendowifi*=0.0.0.0\n"
    "wii.com=0.0.0.0\n"
    "*.wii.com=0.0.0.0\n"
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
    "ubisoft.com=0.0.0.0\n"
    "*.ubisoft.com=0.0.0.0\n"
    "ubi.com=0.0.0.0\n"
    "*.ubi.com=0.0.0.0\n"
    "ubisoftconnect.com=0.0.0.0\n"
    "*.ubisoftconnect.com=0.0.0.0\n"
    "ubi-services.com=0.0.0.0\n"
    "*.ubi-services.com=0.0.0.0\n"
    "sega.com=0.0.0.0\n"
    "*.sega.com=0.0.0.0\n"
    "sega.co.jp=0.0.0.0\n"
    "*.sega.co.jp=0.0.0.0\n"
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
    "# Legacy Encore rules (exact names already covered by existing wildcard removed).\n"
    "scsi-upload-lp1.s3.us-west-2.amazonaws.com=0.0.0.0\n"
    "rocketleague.com=0.0.0.0\n"
    "psyonix.com=0.0.0.0\n"
    "fallguys.com=0.0.0.0\n"
    "codemasters.com=0.0.0.0\n"
    "microsoft.com=0.0.0.0\n"
    "minecraft.net=0.0.0.0\n"
    "minecraftservices.com=0.0.0.0\n"
    "mojang.com=0.0.0.0\n"
    "atlus.co.jp=0.0.0.0\n"
    "capcom.co.jp=0.0.0.0\n"
    "square-enix-games.com=0.0.0.0\n"
    "square-enix.co.jp=0.0.0.0\n"
    "fromsoftware.jp=0.0.0.0\n"
    "konami.com=0.0.0.0\n"
    "konami.net=0.0.0.0\n"
    "yugioh-card.com=0.0.0.0\n"
    "activision.com=0.0.0.0\n"
    "callofduty.com=0.0.0.0\n"
    "demonware.net=0.0.0.0\n"
    "demonware.com=0.0.0.0\n"
    "blizzard.com=0.0.0.0\n"
    "battle.net=0.0.0.0\n"
    "bethesda.net=0.0.0.0\n"
    "bethesda.com=0.0.0.0\n"
    "zenimax.com=0.0.0.0\n"
    "gearboxsoftware.com=0.0.0.0\n"
    "wbgames.com=0.0.0.0\n"
    "wbplay.com=0.0.0.0\n"
    "warnerbrosgames.com=0.0.0.0\n"
    "ttgames.com=0.0.0.0\n"
    "koeitecmo.com=0.0.0.0\n"
    "koeitecmoamerica.com=0.0.0.0\n"
    "koeitecmo.co.jp=0.0.0.0\n"
    "gamecity.ne.jp=0.0.0.0\n"
    "level5.co.jp=0.0.0.0\n"
    "marvelous.co.jp=0.0.0.0\n"
    "nisamerica.com=0.0.0.0\n"
    "nippon1.co.jp=0.0.0.0\n"
    "spike-chunsoft.com=0.0.0.0\n"
    "spike-chunsoft.co.jp=0.0.0.0\n"
    "arcsystemworks.com=0.0.0.0\n"
    "arcsygames.com=0.0.0.0\n"
    "inticreates.com=0.0.0.0\n"
    "gungho.jp=0.0.0.0\n"
    "505games.com=0.0.0.0\n"
    "team17.com=0.0.0.0\n"
    "thqnordic.com=0.0.0.0\n"
    "plaion.com=0.0.0.0\n"
    "deep-silver.com=0.0.0.0\n"
    "tinybuild.com=0.0.0.0\n"
    "devolverdigital.com=0.0.0.0\n"
    "nacon.com=0.0.0.0\n"
    "maximumgames.com=0.0.0.0\n"
    "rawfury.com=0.0.0.0\n"
    "annapurnainteractive.com=0.0.0.0\n"
    "humblegames.com=0.0.0.0\n"
    "curvegames.com=0.0.0.0\n"
    "dotemu.com=0.0.0.0\n"
    "microids.com=0.0.0.0\n"
    "telltale.com=0.0.0.0\n"
    "jackboxgames.com=0.0.0.0\n"
    "jackbox.tv=0.0.0.0\n"
    "playdigious.com=0.0.0.0\n"
    "warframe.com=0.0.0.0\n"
    "digitalextremes.com=0.0.0.0\n"
    "deadbydaylight.com=0.0.0.0\n"
    "bhvr.com=0.0.0.0\n"
    "hirezstudios.com=0.0.0.0\n"
    "smitegame.com=0.0.0.0\n"
    "pokemon.com=0.0.0.0\n"
    "pokemon.co.jp=0.0.0.0\n"
    "pokemonunite.com=0.0.0.0\n"
    "\n"
    "# Legacy publisher suffix completion (72 additions)\n"
    "*.rocketleague.com=0.0.0.0\n"
    "*.psyonix.com=0.0.0.0\n"
    "*.fallguys.com=0.0.0.0\n"
    "*.codemasters.com=0.0.0.0\n"
    "*.minecraft.net=0.0.0.0\n"
    "*.minecraftservices.com=0.0.0.0\n"
    "*.mojang.com=0.0.0.0\n"
    "*.atlus.co.jp=0.0.0.0\n"
    "*.capcom.co.jp=0.0.0.0\n"
    "*.square-enix-games.com=0.0.0.0\n"
    "*.square-enix.co.jp=0.0.0.0\n"
    "*.fromsoftware.jp=0.0.0.0\n"
    "*.konami.com=0.0.0.0\n"
    "*.konami.net=0.0.0.0\n"
    "*.yugioh-card.com=0.0.0.0\n"
    "*.activision.com=0.0.0.0\n"
    "*.callofduty.com=0.0.0.0\n"
    "*.demonware.net=0.0.0.0\n"
    "*.demonware.com=0.0.0.0\n"
    "*.blizzard.com=0.0.0.0\n"
    "*.battle.net=0.0.0.0\n"
    "*.bethesda.net=0.0.0.0\n"
    "*.bethesda.com=0.0.0.0\n"
    "*.zenimax.com=0.0.0.0\n"
    "*.gearboxsoftware.com=0.0.0.0\n"
    "*.phoenix-api.wbagora.com=0.0.0.0\n"
    "*.wbgames.com=0.0.0.0\n"
    "*.wbplay.com=0.0.0.0\n"
    "*.warnerbrosgames.com=0.0.0.0\n"
    "*.ttgames.com=0.0.0.0\n"
    "*.koeitecmo.com=0.0.0.0\n"
    "*.koeitecmoamerica.com=0.0.0.0\n"
    "*.koeitecmo.co.jp=0.0.0.0\n"
    "*.gamecity.ne.jp=0.0.0.0\n"
    "*.level5.co.jp=0.0.0.0\n"
    "*.marvelous.co.jp=0.0.0.0\n"
    "*.nisamerica.com=0.0.0.0\n"
    "*.nippon1.co.jp=0.0.0.0\n"
    "*.spike-chunsoft.com=0.0.0.0\n"
    "*.spike-chunsoft.co.jp=0.0.0.0\n"
    "*.arcsystemworks.com=0.0.0.0\n"
    "*.arcsygames.com=0.0.0.0\n"
    "*.inticreates.com=0.0.0.0\n"
    "*.gungho.jp=0.0.0.0\n"
    "*.505games.com=0.0.0.0\n"
    "*.team17.com=0.0.0.0\n"
    "*.thqnordic.com=0.0.0.0\n"
    "*.plaion.com=0.0.0.0\n"
    "*.deep-silver.com=0.0.0.0\n"
    "*.tinybuild.com=0.0.0.0\n"
    "*.devolverdigital.com=0.0.0.0\n"
    "*.nacon.com=0.0.0.0\n"
    "*.maximumgames.com=0.0.0.0\n"
    "*.rawfury.com=0.0.0.0\n"
    "*.annapurnainteractive.com=0.0.0.0\n"
    "*.humblegames.com=0.0.0.0\n"
    "*.curvegames.com=0.0.0.0\n"
    "*.dotemu.com=0.0.0.0\n"
    "*.microids.com=0.0.0.0\n"
    "*.telltale.com=0.0.0.0\n"
    "*.jackboxgames.com=0.0.0.0\n"
    "*.jackbox.tv=0.0.0.0\n"
    "*.playdigious.com=0.0.0.0\n"
    "*.warframe.com=0.0.0.0\n"
    "*.digitalextremes.com=0.0.0.0\n"
    "*.deadbydaylight.com=0.0.0.0\n"
    "*.bhvr.com=0.0.0.0\n"
    "*.hirezstudios.com=0.0.0.0\n"
    "*.smitegame.com=0.0.0.0\n"
    "*.pokemon.com=0.0.0.0\n"
    "*.pokemon.co.jp=0.0.0.0\n"
    "*.pokemonunite.com=0.0.0.0\n"
    "\n"
    "# Platforms and dedicated game distribution (40 additions)\n"
    "steamgames.com=0.0.0.0\n"
    "*.steamgames.com=0.0.0.0\n"
    "steamstatic.com=0.0.0.0\n"
    "*.steamstatic.com=0.0.0.0\n"
    "steamcontent.com=0.0.0.0\n"
    "*.steamcontent.com=0.0.0.0\n"
    "steamserver.net=0.0.0.0\n"
    "*.steamserver.net=0.0.0.0\n"
    "steamusercontent.com=0.0.0.0\n"
    "*.steamusercontent.com=0.0.0.0\n"
    "steamdeck.com=0.0.0.0\n"
    "*.steamdeck.com=0.0.0.0\n"
    "steambroadcast.com=0.0.0.0\n"
    "*.steambroadcast.com=0.0.0.0\n"
    "steam-chat.com=0.0.0.0\n"
    "*.steam-chat.com=0.0.0.0\n"
    "steam.tv=0.0.0.0\n"
    "*.steam.tv=0.0.0.0\n"
    "xboxgamepass.com=0.0.0.0\n"
    "*.xboxgamepass.com=0.0.0.0\n"
    "xboxstudios.com=0.0.0.0\n"
    "*.xboxstudios.com=0.0.0.0\n"
    "playfabapi.com=0.0.0.0\n"
    "*.playfabapi.com=0.0.0.0\n"
    "playfab.com=0.0.0.0\n"
    "*.playfab.com=0.0.0.0\n"
    "humblebundle.com=0.0.0.0\n"
    "*.humblebundle.com=0.0.0.0\n"
    "epicgames-download1.akamaized.net=0.0.0.0\n"
    "*.epicgames-download1.akamaized.net=0.0.0.0\n"
    "epicgames-download2.akamaized.net=0.0.0.0\n"
    "*.epicgames-download2.akamaized.net=0.0.0.0\n"
    "eaassets-a.akamaihd.net=0.0.0.0\n"
    "*.eaassets-a.akamaihd.net=0.0.0.0\n"
    "origin-a.akamaihd.net=0.0.0.0\n"
    "*.origin-a.akamaihd.net=0.0.0.0\n"
    "ubistatic.com=0.0.0.0\n"
    "*.ubistatic.com=0.0.0.0\n"
    "ubistatic2-a.akamaihd.net=0.0.0.0\n"
    "*.ubistatic2-a.akamaihd.net=0.0.0.0\n"
    "\n"
    "# PlayStation studios and partners (44 additions)\n"
    "bungie.net=0.0.0.0\n"
    "*.bungie.net=0.0.0.0\n"
    "bungie.com=0.0.0.0\n"
    "*.bungie.com=0.0.0.0\n"
    "destinythegame.com=0.0.0.0\n"
    "*.destinythegame.com=0.0.0.0\n"
    "naughtydog.com=0.0.0.0\n"
    "*.naughtydog.com=0.0.0.0\n"
    "insomniac.games=0.0.0.0\n"
    "*.insomniac.games=0.0.0.0\n"
    "guerrilla-games.com=0.0.0.0\n"
    "*.guerrilla-games.com=0.0.0.0\n"
    "santamonicastudio.com=0.0.0.0\n"
    "*.santamonicastudio.com=0.0.0.0\n"
    "suckerpunch.com=0.0.0.0\n"
    "*.suckerpunch.com=0.0.0.0\n"
    "bendstudio.com=0.0.0.0\n"
    "*.bendstudio.com=0.0.0.0\n"
    "polyphony.co.jp=0.0.0.0\n"
    "*.polyphony.co.jp=0.0.0.0\n"
    "gran-turismo.com=0.0.0.0\n"
    "*.gran-turismo.com=0.0.0.0\n"
    "housemarque.com=0.0.0.0\n"
    "*.housemarque.com=0.0.0.0\n"
    "firesprite.com=0.0.0.0\n"
    "*.firesprite.com=0.0.0.0\n"
    "bluepointgames.com=0.0.0.0\n"
    "*.bluepointgames.com=0.0.0.0\n"
    "mediamolecule.com=0.0.0.0\n"
    "*.mediamolecule.com=0.0.0.0\n"
    "havenstudios.com=0.0.0.0\n"
    "*.havenstudios.com=0.0.0.0\n"
    "arrowheadgamestudios.com=0.0.0.0\n"
    "*.arrowheadgamestudios.com=0.0.0.0\n"
    "helldivers.com=0.0.0.0\n"
    "*.helldivers.com=0.0.0.0\n"
    "kojimaproductions.jp=0.0.0.0\n"
    "*.kojimaproductions.jp=0.0.0.0\n"
    "quanticdream.com=0.0.0.0\n"
    "*.quanticdream.com=0.0.0.0\n"
    "shiftup.co.kr=0.0.0.0\n"
    "*.shiftup.co.kr=0.0.0.0\n"
    "stellarblade.com=0.0.0.0\n"
    "*.stellarblade.com=0.0.0.0\n"
    "\n"
    "# Major international publishers and online games (184 additions)\n"
    "riotgames.com=0.0.0.0\n"
    "*.riotgames.com=0.0.0.0\n"
    "riotgames.net=0.0.0.0\n"
    "*.riotgames.net=0.0.0.0\n"
    "riotcdn.net=0.0.0.0\n"
    "*.riotcdn.net=0.0.0.0\n"
    "leagueoflegends.com=0.0.0.0\n"
    "*.leagueoflegends.com=0.0.0.0\n"
    "playvalorant.com=0.0.0.0\n"
    "*.playvalorant.com=0.0.0.0\n"
    "valorant.com=0.0.0.0\n"
    "*.valorant.com=0.0.0.0\n"
    "teamfighttactics.com=0.0.0.0\n"
    "*.teamfighttactics.com=0.0.0.0\n"
    "lolesports.com=0.0.0.0\n"
    "*.lolesports.com=0.0.0.0\n"
    "netease.com=0.0.0.0\n"
    "*.netease.com=0.0.0.0\n"
    "neteasegames.com=0.0.0.0\n"
    "*.neteasegames.com=0.0.0.0\n"
    "marvelrivals.com=0.0.0.0\n"
    "*.marvelrivals.com=0.0.0.0\n"
    "wherewindsmeetgame.com=0.0.0.0\n"
    "*.wherewindsmeetgame.com=0.0.0.0\n"
    "oncehuman.game=0.0.0.0\n"
    "*.oncehuman.game=0.0.0.0\n"
    "identityvgame.com=0.0.0.0\n"
    "*.identityvgame.com=0.0.0.0\n"
    "narakabladepoint.com=0.0.0.0\n"
    "*.narakabladepoint.com=0.0.0.0\n"
    "tencentgames.com=0.0.0.0\n"
    "*.tencentgames.com=0.0.0.0\n"
    "levelinfinite.com=0.0.0.0\n"
    "*.levelinfinite.com=0.0.0.0\n"
    "lightspeed-studios.com=0.0.0.0\n"
    "*.lightspeed-studios.com=0.0.0.0\n"
    "timistudios.com=0.0.0.0\n"
    "*.timistudios.com=0.0.0.0\n"
    "pubg.com=0.0.0.0\n"
    "*.pubg.com=0.0.0.0\n"
    "pubgmobile.com=0.0.0.0\n"
    "*.pubgmobile.com=0.0.0.0\n"
    "krafton.com=0.0.0.0\n"
    "*.krafton.com=0.0.0.0\n"
    "playbattlegrounds.com=0.0.0.0\n"
    "*.playbattlegrounds.com=0.0.0.0\n"
    "nexon.com=0.0.0.0\n"
    "*.nexon.com=0.0.0.0\n"
    "nexon.net=0.0.0.0\n"
    "*.nexon.net=0.0.0.0\n"
    "nexon.co.jp=0.0.0.0\n"
    "*.nexon.co.jp=0.0.0.0\n"
    "maplestory.com=0.0.0.0\n"
    "*.maplestory.com=0.0.0.0\n"
    "dungeonfighteronline.com=0.0.0.0\n"
    "*.dungeonfighteronline.com=0.0.0.0\n"
    "neople.co.kr=0.0.0.0\n"
    "*.neople.co.kr=0.0.0.0\n"
    "pearlabyss.com=0.0.0.0\n"
    "*.pearlabyss.com=0.0.0.0\n"
    "playblackdesert.com=0.0.0.0\n"
    "*.playblackdesert.com=0.0.0.0\n"
    "blackdesertonline.com=0.0.0.0\n"
    "*.blackdesertonline.com=0.0.0.0\n"
    "crimsondesert.com=0.0.0.0\n"
    "*.crimsondesert.com=0.0.0.0\n"
    "ncsoft.com=0.0.0.0\n"
    "*.ncsoft.com=0.0.0.0\n"
    "plaync.com=0.0.0.0\n"
    "*.plaync.com=0.0.0.0\n"
    "guildwars2.com=0.0.0.0\n"
    "*.guildwars2.com=0.0.0.0\n"
    "arena.net=0.0.0.0\n"
    "*.arena.net=0.0.0.0\n"
    "arenanet.com=0.0.0.0\n"
    "*.arenanet.com=0.0.0.0\n"
    "throneandliberty.com=0.0.0.0\n"
    "*.throneandliberty.com=0.0.0.0\n"
    "kakaogames.com=0.0.0.0\n"
    "*.kakaogames.com=0.0.0.0\n"
    "kakaogamescorp.com=0.0.0.0\n"
    "*.kakaogamescorp.com=0.0.0.0\n"
    "neowiz.com=0.0.0.0\n"
    "*.neowiz.com=0.0.0.0\n"
    "neowiz.co.kr=0.0.0.0\n"
    "*.neowiz.co.kr=0.0.0.0\n"
    "liesofp.com=0.0.0.0\n"
    "*.liesofp.com=0.0.0.0\n"
    "smilegate.com=0.0.0.0\n"
    "*.smilegate.com=0.0.0.0\n"
    "onstove.com=0.0.0.0\n"
    "*.onstove.com=0.0.0.0\n"
    "lostark.game=0.0.0.0\n"
    "*.lostark.game=0.0.0.0\n"
    "amazongames.com=0.0.0.0\n"
    "*.amazongames.com=0.0.0.0\n"
    "newworld.com=0.0.0.0\n"
    "*.newworld.com=0.0.0.0\n"
    "playlostark.com=0.0.0.0\n"
    "*.playlostark.com=0.0.0.0\n"
    "mihoyo.com=0.0.0.0\n"
    "*.mihoyo.com=0.0.0.0\n"
    "hoyoverse.com=0.0.0.0\n"
    "*.hoyoverse.com=0.0.0.0\n"
    "hoyolab.com=0.0.0.0\n"
    "*.hoyolab.com=0.0.0.0\n"
    "genshinimpact.com=0.0.0.0\n"
    "*.genshinimpact.com=0.0.0.0\n"
    "honkaiimpact3.com=0.0.0.0\n"
    "*.honkaiimpact3.com=0.0.0.0\n"
    "honkaistarrail.com=0.0.0.0\n"
    "*.honkaistarrail.com=0.0.0.0\n"
    "zenlesszonezero.com=0.0.0.0\n"
    "*.zenlesszonezero.com=0.0.0.0\n"
    "kurogames.com=0.0.0.0\n"
    "*.kurogames.com=0.0.0.0\n"
    "wutheringwaves.com=0.0.0.0\n"
    "*.wutheringwaves.com=0.0.0.0\n"
    "perfectworld.com=0.0.0.0\n"
    "*.perfectworld.com=0.0.0.0\n"
    "perfectworldgames.com=0.0.0.0\n"
    "*.perfectworldgames.com=0.0.0.0\n"
    "arcgames.com=0.0.0.0\n"
    "*.arcgames.com=0.0.0.0\n"
    "my.games=0.0.0.0\n"
    "*.my.games=0.0.0.0\n"
    "wargaming.net=0.0.0.0\n"
    "*.wargaming.net=0.0.0.0\n"
    "worldoftanks.com=0.0.0.0\n"
    "*.worldoftanks.com=0.0.0.0\n"
    "worldofwarships.com=0.0.0.0\n"
    "*.worldofwarships.com=0.0.0.0\n"
    "gaijin.net=0.0.0.0\n"
    "*.gaijin.net=0.0.0.0\n"
    "gaijinent.com=0.0.0.0\n"
    "*.gaijinent.com=0.0.0.0\n"
    "warthunder.com=0.0.0.0\n"
    "*.warthunder.com=0.0.0.0\n"
    "crossout.net=0.0.0.0\n"
    "*.crossout.net=0.0.0.0\n"
    "enlisted.net=0.0.0.0\n"
    "*.enlisted.net=0.0.0.0\n"
    "roblox.com=0.0.0.0\n"
    "*.roblox.com=0.0.0.0\n"
    "rbxcdn.com=0.0.0.0\n"
    "*.rbxcdn.com=0.0.0.0\n"
    "roblox.net=0.0.0.0\n"
    "*.roblox.net=0.0.0.0\n"
    "jagex.com=0.0.0.0\n"
    "*.jagex.com=0.0.0.0\n"
    "runescape.com=0.0.0.0\n"
    "*.runescape.com=0.0.0.0\n"
    "funcom.com=0.0.0.0\n"
    "*.funcom.com=0.0.0.0\n"
    "conanexiles.com=0.0.0.0\n"
    "*.conanexiles.com=0.0.0.0\n"
    "duneawakening.com=0.0.0.0\n"
    "*.duneawakening.com=0.0.0.0\n"
    "starbreeze.com=0.0.0.0\n"
    "*.starbreeze.com=0.0.0.0\n"
    "paydaythegame.com=0.0.0.0\n"
    "*.paydaythegame.com=0.0.0.0\n"
    "embark-studios.com=0.0.0.0\n"
    "*.embark-studios.com=0.0.0.0\n"
    "reachthefinals.com=0.0.0.0\n"
    "*.reachthefinals.com=0.0.0.0\n"
    "arcraiders.com=0.0.0.0\n"
    "*.arcraiders.com=0.0.0.0\n"
    "facepunch.com=0.0.0.0\n"
    "*.facepunch.com=0.0.0.0\n"
    "bohemia.net=0.0.0.0\n"
    "*.bohemia.net=0.0.0.0\n"
    "bistudio.com=0.0.0.0\n"
    "*.bistudio.com=0.0.0.0\n"
    "dayz.com=0.0.0.0\n"
    "*.dayz.com=0.0.0.0\n"
    "arma3.com=0.0.0.0\n"
    "*.arma3.com=0.0.0.0\n"
    "armaplatform.com=0.0.0.0\n"
    "*.armaplatform.com=0.0.0.0\n"
    "battlestategames.com=0.0.0.0\n"
    "*.battlestategames.com=0.0.0.0\n"
    "escapefromtarkov.com=0.0.0.0\n"
    "*.escapefromtarkov.com=0.0.0.0\n"
    "\n"
    "# Japan and Asia publishers (204 additions)\n"
    "bandainamco.co.jp=0.0.0.0\n"
    "*.bandainamco.co.jp=0.0.0.0\n"
    "bandainamcoent.co.jp=0.0.0.0\n"
    "*.bandainamcoent.co.jp=0.0.0.0\n"
    "bandainamcoent.eu=0.0.0.0\n"
    "*.bandainamcoent.eu=0.0.0.0\n"
    "bandainamcoent.asia=0.0.0.0\n"
    "*.bandainamcoent.asia=0.0.0.0\n"
    "bandainamcogames.co.jp=0.0.0.0\n"
    "*.bandainamcogames.co.jp=0.0.0.0\n"
    "bn-ent.net=0.0.0.0\n"
    "*.bn-ent.net=0.0.0.0\n"
    "bn765.com=0.0.0.0\n"
    "*.bn765.com=0.0.0.0\n"
    "bandainamcoid.com=0.0.0.0\n"
    "*.bandainamcoid.com=0.0.0.0\n"
    "capcom-games.com=0.0.0.0\n"
    "*.capcom-games.com=0.0.0.0\n"
    "capcomusa.com=0.0.0.0\n"
    "*.capcomusa.com=0.0.0.0\n"
    "capcom-europe.com=0.0.0.0\n"
    "*.capcom-europe.com=0.0.0.0\n"
    "capcomid.com=0.0.0.0\n"
    "*.capcomid.com=0.0.0.0\n"
    "monsterhunter.com=0.0.0.0\n"
    "*.monsterhunter.com=0.0.0.0\n"
    "residentevil.com=0.0.0.0\n"
    "*.residentevil.com=0.0.0.0\n"
    "streetfighter.com=0.0.0.0\n"
    "*.streetfighter.com=0.0.0.0\n"
    "konami.co.jp=0.0.0.0\n"
    "*.konami.co.jp=0.0.0.0\n"
    "efootball.com=0.0.0.0\n"
    "*.efootball.com=0.0.0.0\n"
    "square-enix.net=0.0.0.0\n"
    "*.square-enix.net=0.0.0.0\n"
    "square-enix-europe.com=0.0.0.0\n"
    "*.square-enix-europe.com=0.0.0.0\n"
    "finalfantasy.com=0.0.0.0\n"
    "*.finalfantasy.com=0.0.0.0\n"
    "finalfantasyxiv.com=0.0.0.0\n"
    "*.finalfantasyxiv.com=0.0.0.0\n"
    "ffxiv.com=0.0.0.0\n"
    "*.ffxiv.com=0.0.0.0\n"
    "dragonquest.com=0.0.0.0\n"
    "*.dragonquest.com=0.0.0.0\n"
    "kingdomhearts.com=0.0.0.0\n"
    "*.kingdomhearts.com=0.0.0.0\n"
    "sega.net=0.0.0.0\n"
    "*.sega.net=0.0.0.0\n"
    "sega.jp=0.0.0.0\n"
    "*.sega.jp=0.0.0.0\n"
    "sega-europe.com=0.0.0.0\n"
    "*.sega-europe.com=0.0.0.0\n"
    "sonicthehedgehog.com=0.0.0.0\n"
    "*.sonicthehedgehog.com=0.0.0.0\n"
    "atlus.com=0.0.0.0\n"
    "*.atlus.com=0.0.0.0\n"
    "persona.com=0.0.0.0\n"
    "*.persona.com=0.0.0.0\n"
    "ryugagotoku.com=0.0.0.0\n"
    "*.ryugagotoku.com=0.0.0.0\n"
    "cygames.co.jp=0.0.0.0\n"
    "*.cygames.co.jp=0.0.0.0\n"
    "cygames.com=0.0.0.0\n"
    "*.cygames.com=0.0.0.0\n"
    "cygameseurope.com=0.0.0.0\n"
    "*.cygameseurope.com=0.0.0.0\n"
    "granbluefantasy.jp=0.0.0.0\n"
    "*.granbluefantasy.jp=0.0.0.0\n"
    "granbluefantasy.com=0.0.0.0\n"
    "*.granbluefantasy.com=0.0.0.0\n"
    "shadowverse.com=0.0.0.0\n"
    "*.shadowverse.com=0.0.0.0\n"
    "umamusume.com=0.0.0.0\n"
    "*.umamusume.com=0.0.0.0\n"
    "gunghoonline.com=0.0.0.0\n"
    "*.gunghoonline.com=0.0.0.0\n"
    "gungho.co.jp=0.0.0.0\n"
    "*.gungho.co.jp=0.0.0.0\n"
    "gungho.com=0.0.0.0\n"
    "*.gungho.com=0.0.0.0\n"
    "marvelousgames.com=0.0.0.0\n"
    "*.marvelousgames.com=0.0.0.0\n"
    "marvelous-usa.com=0.0.0.0\n"
    "*.marvelous-usa.com=0.0.0.0\n"
    "xseedgames.com=0.0.0.0\n"
    "*.xseedgames.com=0.0.0.0\n"
    "falcom.co.jp=0.0.0.0\n"
    "*.falcom.co.jp=0.0.0.0\n"
    "aksysgames.com=0.0.0.0\n"
    "*.aksysgames.com=0.0.0.0\n"
    "idea-factory.co.jp=0.0.0.0\n"
    "*.idea-factory.co.jp=0.0.0.0\n"
    "ideafintl.com=0.0.0.0\n"
    "*.ideafintl.com=0.0.0.0\n"
    "compileheart.com=0.0.0.0\n"
    "*.compileheart.com=0.0.0.0\n"
    "nippon1.jp=0.0.0.0\n"
    "*.nippon1.jp=0.0.0.0\n"
    "snk-corp.co.jp=0.0.0.0\n"
    "*.snk-corp.co.jp=0.0.0.0\n"
    "snk-corp.com=0.0.0.0\n"
    "*.snk-corp.com=0.0.0.0\n"
    "kemco.jp=0.0.0.0\n"
    "*.kemco.jp=0.0.0.0\n"
    "kemco-games.com=0.0.0.0\n"
    "*.kemco-games.com=0.0.0.0\n"
    "hamster.co.jp=0.0.0.0\n"
    "*.hamster.co.jp=0.0.0.0\n"
    "sunsoft.jp=0.0.0.0\n"
    "*.sunsoft.jp=0.0.0.0\n"
    "taito.co.jp=0.0.0.0\n"
    "*.taito.co.jp=0.0.0.0\n"
    "success-corp.co.jp=0.0.0.0\n"
    "*.success-corp.co.jp=0.0.0.0\n"
    "mages.co.jp=0.0.0.0\n"
    "*.mages.co.jp=0.0.0.0\n"
    "d3p.co.jp=0.0.0.0\n"
    "*.d3p.co.jp=0.0.0.0\n"
    "d3publisher.com=0.0.0.0\n"
    "*.d3publisher.com=0.0.0.0\n"
    "acquire.co.jp=0.0.0.0\n"
    "*.acquire.co.jp=0.0.0.0\n"
    "experience.co.jp=0.0.0.0\n"
    "*.experience.co.jp=0.0.0.0\n"
    "inti.co.jp=0.0.0.0\n"
    "*.inti.co.jp=0.0.0.0\n"
    "level5.com=0.0.0.0\n"
    "*.level5.com=0.0.0.0\n"
    "level5abby.com=0.0.0.0\n"
    "*.level5abby.com=0.0.0.0\n"
    "koei.co.jp=0.0.0.0\n"
    "*.koei.co.jp=0.0.0.0\n"
    "teamninja-studio.com=0.0.0.0\n"
    "*.teamninja-studio.com=0.0.0.0\n"
    "gust.jp=0.0.0.0\n"
    "*.gust.jp=0.0.0.0\n"
    "natsume.com=0.0.0.0\n"
    "*.natsume.com=0.0.0.0\n"
    "natsumeatari.co.jp=0.0.0.0\n"
    "*.natsumeatari.co.jp=0.0.0.0\n"
    "gamefreak.co.jp=0.0.0.0\n"
    "*.gamefreak.co.jp=0.0.0.0\n"
    "creatures.co.jp=0.0.0.0\n"
    "*.creatures.co.jp=0.0.0.0\n"
    "pokemoncenter.com=0.0.0.0\n"
    "*.pokemoncenter.com=0.0.0.0\n"
    "pokemongolive.com=0.0.0.0\n"
    "*.pokemongolive.com=0.0.0.0\n"
    "nianticlabs.com=0.0.0.0\n"
    "*.nianticlabs.com=0.0.0.0\n"
    "dena.com=0.0.0.0\n"
    "*.dena.com=0.0.0.0\n"
    "dena.jp=0.0.0.0\n"
    "*.dena.jp=0.0.0.0\n"
    "gree.net=0.0.0.0\n"
    "*.gree.net=0.0.0.0\n"
    "gree.co.jp=0.0.0.0\n"
    "*.gree.co.jp=0.0.0.0\n"
    "colopl.co.jp=0.0.0.0\n"
    "*.colopl.co.jp=0.0.0.0\n"
    "aniplex.co.jp=0.0.0.0\n"
    "*.aniplex.co.jp=0.0.0.0\n"
    "aniplexusa.com=0.0.0.0\n"
    "*.aniplexusa.com=0.0.0.0\n"
    "bushiroad.com=0.0.0.0\n"
    "*.bushiroad.com=0.0.0.0\n"
    "bushiroadgames.com=0.0.0.0\n"
    "*.bushiroadgames.com=0.0.0.0\n"
    "gamesourceentertainment.com=0.0.0.0\n"
    "*.gamesourceentertainment.com=0.0.0.0\n"
    "eastasiasoft.com=0.0.0.0\n"
    "*.eastasiasoft.com=0.0.0.0\n"
    "joycity.com=0.0.0.0\n"
    "*.joycity.com=0.0.0.0\n"
    "com2us.com=0.0.0.0\n"
    "*.com2us.com=0.0.0.0\n"
    "gamevil.com=0.0.0.0\n"
    "*.gamevil.com=0.0.0.0\n"
    "webzen.com=0.0.0.0\n"
    "*.webzen.com=0.0.0.0\n"
    "gravity.co.kr=0.0.0.0\n"
    "*.gravity.co.kr=0.0.0.0\n"
    "gravityus.com=0.0.0.0\n"
    "*.gravityus.com=0.0.0.0\n"
    "playragnarok.com=0.0.0.0\n"
    "*.playragnarok.com=0.0.0.0\n"
    "wemade.com=0.0.0.0\n"
    "*.wemade.com=0.0.0.0\n"
    "line.games=0.0.0.0\n"
    "*.line.games=0.0.0.0\n"
    "hangame.com=0.0.0.0\n"
    "*.hangame.com=0.0.0.0\n"
    "hangame.co.jp=0.0.0.0\n"
    "*.hangame.co.jp=0.0.0.0\n"
    "nexon.co.kr=0.0.0.0\n"
    "*.nexon.co.kr=0.0.0.0\n"
    "netmarble.com=0.0.0.0\n"
    "*.netmarble.com=0.0.0.0\n"
    "netmarble.net=0.0.0.0\n"
    "*.netmarble.net=0.0.0.0\n"
    "netmarble.co.kr=0.0.0.0\n"
    "*.netmarble.co.kr=0.0.0.0\n"
    "\n"
    "# Western publishers, labels and studios (280 additions)\n"
    "focus-entmt.com=0.0.0.0\n"
    "*.focus-entmt.com=0.0.0.0\n"
    "focus-home.com=0.0.0.0\n"
    "*.focus-home.com=0.0.0.0\n"
    "focusentertainment.com=0.0.0.0\n"
    "*.focusentertainment.com=0.0.0.0\n"
    "pullupent.com=0.0.0.0\n"
    "*.pullupent.com=0.0.0.0\n"
    "saber.games=0.0.0.0\n"
    "*.saber.games=0.0.0.0\n"
    "saber3d.com=0.0.0.0\n"
    "*.saber3d.com=0.0.0.0\n"
    "saberinteractive.com=0.0.0.0\n"
    "*.saberinteractive.com=0.0.0.0\n"
    "embracer.com=0.0.0.0\n"
    "*.embracer.com=0.0.0.0\n"
    "asmodee.com=0.0.0.0\n"
    "*.asmodee.com=0.0.0.0\n"
    "kochmedia.com=0.0.0.0\n"
    "*.kochmedia.com=0.0.0.0\n"
    "primematter.gg=0.0.0.0\n"
    "*.primematter.gg=0.0.0.0\n"
    "coffeestain.com=0.0.0.0\n"
    "*.coffeestain.com=0.0.0.0\n"
    "coffeestainstudios.com=0.0.0.0\n"
    "*.coffeestainstudios.com=0.0.0.0\n"
    "ghostship.dk=0.0.0.0\n"
    "*.ghostship.dk=0.0.0.0\n"
    "deeprockgalactic.com=0.0.0.0\n"
    "*.deeprockgalactic.com=0.0.0.0\n"
    "easybrain.com=0.0.0.0\n"
    "*.easybrain.com=0.0.0.0\n"
    "amplifiergameinvest.com=0.0.0.0\n"
    "*.amplifiergameinvest.com=0.0.0.0\n"
    "flyingwildhog.com=0.0.0.0\n"
    "*.flyingwildhog.com=0.0.0.0\n"
    "warhorse-studios.com=0.0.0.0\n"
    "*.warhorse-studios.com=0.0.0.0\n"
    "kingdomcomerpg.com=0.0.0.0\n"
    "*.kingdomcomerpg.com=0.0.0.0\n"
    "milestone.it=0.0.0.0\n"
    "*.milestone.it=0.0.0.0\n"
    "ridevideogame.com=0.0.0.0\n"
    "*.ridevideogame.com=0.0.0.0\n"
    "motogpvideogame.com=0.0.0.0\n"
    "*.motogpvideogame.com=0.0.0.0\n"
    "remedyentertainment.com=0.0.0.0\n"
    "*.remedyentertainment.com=0.0.0.0\n"
    "alanwake.com=0.0.0.0\n"
    "*.alanwake.com=0.0.0.0\n"
    "controlgame.com=0.0.0.0\n"
    "*.controlgame.com=0.0.0.0\n"
    "techland.net=0.0.0.0\n"
    "*.techland.net=0.0.0.0\n"
    "techland.pl=0.0.0.0\n"
    "*.techland.pl=0.0.0.0\n"
    "dyinglightgame.com=0.0.0.0\n"
    "*.dyinglightgame.com=0.0.0.0\n"
    "paradoxinteractive.com=0.0.0.0\n"
    "*.paradoxinteractive.com=0.0.0.0\n"
    "paradoxplaza.com=0.0.0.0\n"
    "*.paradoxplaza.com=0.0.0.0\n"
    "paradoxwikis.com=0.0.0.0\n"
    "*.paradoxwikis.com=0.0.0.0\n"
    "colossalorder.fi=0.0.0.0\n"
    "*.colossalorder.fi=0.0.0.0\n"
    "triumphstudios.com=0.0.0.0\n"
    "*.triumphstudios.com=0.0.0.0\n"
    "harebrained-schemes.com=0.0.0.0\n"
    "*.harebrained-schemes.com=0.0.0.0\n"
    "11bitstudios.com=0.0.0.0\n"
    "*.11bitstudios.com=0.0.0.0\n"
    "frostpunkgame.com=0.0.0.0\n"
    "*.frostpunkgame.com=0.0.0.0\n"
    "larian.com=0.0.0.0\n"
    "*.larian.com=0.0.0.0\n"
    "baldursgate3.game=0.0.0.0\n"
    "*.baldursgate3.game=0.0.0.0\n"
    "owlcat.games=0.0.0.0\n"
    "*.owlcat.games=0.0.0.0\n"
    "inxile-entertainment.com=0.0.0.0\n"
    "*.inxile-entertainment.com=0.0.0.0\n"
    "obsidian.net=0.0.0.0\n"
    "*.obsidian.net=0.0.0.0\n"
    "doublefine.com=0.0.0.0\n"
    "*.doublefine.com=0.0.0.0\n"
    "undeadlabs.com=0.0.0.0\n"
    "*.undeadlabs.com=0.0.0.0\n"
    "playground-games.com=0.0.0.0\n"
    "*.playground-games.com=0.0.0.0\n"
    "turn10studios.com=0.0.0.0\n"
    "*.turn10studios.com=0.0.0.0\n"
    "forza.net=0.0.0.0\n"
    "*.forza.net=0.0.0.0\n"
    "halowaypoint.com=0.0.0.0\n"
    "*.halowaypoint.com=0.0.0.0\n"
    "thecoalitionstudio.com=0.0.0.0\n"
    "*.thecoalitionstudio.com=0.0.0.0\n"
    "rare.co.uk=0.0.0.0\n"
    "*.rare.co.uk=0.0.0.0\n"
    "seaofthieves.com=0.0.0.0\n"
    "*.seaofthieves.com=0.0.0.0\n"
    "machinegames.com=0.0.0.0\n"
    "*.machinegames.com=0.0.0.0\n"
    "idsoftware.com=0.0.0.0\n"
    "*.idsoftware.com=0.0.0.0\n"
    "arkane-studios.com=0.0.0.0\n"
    "*.arkane-studios.com=0.0.0.0\n"
    "tangogameworks.com=0.0.0.0\n"
    "*.tangogameworks.com=0.0.0.0\n"
    "zenimaxonline.com=0.0.0.0\n"
    "*.zenimaxonline.com=0.0.0.0\n"
    "elderscrollsonline.com=0.0.0.0\n"
    "*.elderscrollsonline.com=0.0.0.0\n"
    "elderscrolls.com=0.0.0.0\n"
    "*.elderscrolls.com=0.0.0.0\n"
    "fallout.com=0.0.0.0\n"
    "*.fallout.com=0.0.0.0\n"
    "doom.com=0.0.0.0\n"
    "*.doom.com=0.0.0.0\n"
    "quake.com=0.0.0.0\n"
    "*.quake.com=0.0.0.0\n"
    "wolfenstein.com=0.0.0.0\n"
    "*.wolfenstein.com=0.0.0.0\n"
    "starfieldgame.com=0.0.0.0\n"
    "*.starfieldgame.com=0.0.0.0\n"
    "infinityward.com=0.0.0.0\n"
    "*.infinityward.com=0.0.0.0\n"
    "treyarch.com=0.0.0.0\n"
    "*.treyarch.com=0.0.0.0\n"
    "sledgehammergames.com=0.0.0.0\n"
    "*.sledgehammergames.com=0.0.0.0\n"
    "ravensoftware.com=0.0.0.0\n"
    "*.ravensoftware.com=0.0.0.0\n"
    "highmoonstudios.com=0.0.0.0\n"
    "*.highmoonstudios.com=0.0.0.0\n"
    "beenox.com=0.0.0.0\n"
    "*.beenox.com=0.0.0.0\n"
    "toysforbob.com=0.0.0.0\n"
    "*.toysforbob.com=0.0.0.0\n"
    "king.com=0.0.0.0\n"
    "*.king.com=0.0.0.0\n"
    "candycrush.com=0.0.0.0\n"
    "*.candycrush.com=0.0.0.0\n"
    "blizzard.cn=0.0.0.0\n"
    "*.blizzard.cn=0.0.0.0\n"
    "playoverwatch.com=0.0.0.0\n"
    "*.playoverwatch.com=0.0.0.0\n"
    "diablo.com=0.0.0.0\n"
    "*.diablo.com=0.0.0.0\n"
    "worldofwarcraft.com=0.0.0.0\n"
    "*.worldofwarcraft.com=0.0.0.0\n"
    "hearthstone.com=0.0.0.0\n"
    "*.hearthstone.com=0.0.0.0\n"
    "heroesofthestorm.com=0.0.0.0\n"
    "*.heroesofthestorm.com=0.0.0.0\n"
    "starcraft.com=0.0.0.0\n"
    "*.starcraft.com=0.0.0.0\n"
    "activisionblizzard.com=0.0.0.0\n"
    "*.activisionblizzard.com=0.0.0.0\n"
    "rockstarnorth.com=0.0.0.0\n"
    "*.rockstarnorth.com=0.0.0.0\n"
    "grandtheftauto.com=0.0.0.0\n"
    "*.grandtheftauto.com=0.0.0.0\n"
    "reddeadredemption.com=0.0.0.0\n"
    "*.reddeadredemption.com=0.0.0.0\n"
    "gearboxpublishing.com=0.0.0.0\n"
    "*.gearboxpublishing.com=0.0.0.0\n"
    "borderlands.com=0.0.0.0\n"
    "*.borderlands.com=0.0.0.0\n"
    "firaxis.com=0.0.0.0\n"
    "*.firaxis.com=0.0.0.0\n"
    "civilization.com=0.0.0.0\n"
    "*.civilization.com=0.0.0.0\n"
    "xcom.com=0.0.0.0\n"
    "*.xcom.com=0.0.0.0\n"
    "hangar13games.com=0.0.0.0\n"
    "*.hangar13games.com=0.0.0.0\n"
    "visualconcepts.com=0.0.0.0\n"
    "*.visualconcepts.com=0.0.0.0\n"
    "privatedivision.com=0.0.0.0\n"
    "*.privatedivision.com=0.0.0.0\n"
    "ghoststorygames.com=0.0.0.0\n"
    "*.ghoststorygames.com=0.0.0.0\n"
    "interceptgames.com=0.0.0.0\n"
    "*.interceptgames.com=0.0.0.0\n"
    "roll7.co.uk=0.0.0.0\n"
    "*.roll7.co.uk=0.0.0.0\n"
    "zynga.com=0.0.0.0\n"
    "*.zynga.com=0.0.0.0\n"
    "zyngagames.com=0.0.0.0\n"
    "*.zyngagames.com=0.0.0.0\n"
    "naturalmotion.com=0.0.0.0\n"
    "*.naturalmotion.com=0.0.0.0\n"
    "socialpoint.es=0.0.0.0\n"
    "*.socialpoint.es=0.0.0.0\n"
    "smallgiantgames.com=0.0.0.0\n"
    "*.smallgiantgames.com=0.0.0.0\n"
    "supercell.com=0.0.0.0\n"
    "*.supercell.com=0.0.0.0\n"
    "supercell.net=0.0.0.0\n"
    "*.supercell.net=0.0.0.0\n"
    "clashofclans.com=0.0.0.0\n"
    "*.clashofclans.com=0.0.0.0\n"
    "clashroyale.com=0.0.0.0\n"
    "*.clashroyale.com=0.0.0.0\n"
    "brawlstars.com=0.0.0.0\n"
    "*.brawlstars.com=0.0.0.0\n"
    "hayday.com=0.0.0.0\n"
    "*.hayday.com=0.0.0.0\n"
    "spaceapegames.com=0.0.0.0\n"
    "*.spaceapegames.com=0.0.0.0\n"
    "electronicarts.com=0.0.0.0\n"
    "*.electronicarts.com=0.0.0.0\n"
    "respawn.com=0.0.0.0\n"
    "*.respawn.com=0.0.0.0\n"
    "apexlegends.com=0.0.0.0\n"
    "*.apexlegends.com=0.0.0.0\n"
    "titanfall.com=0.0.0.0\n"
    "*.titanfall.com=0.0.0.0\n"
    "bioware.com=0.0.0.0\n"
    "*.bioware.com=0.0.0.0\n"
    "dice.se=0.0.0.0\n"
    "*.dice.se=0.0.0.0\n"
    "battlefield.com=0.0.0.0\n"
    "*.battlefield.com=0.0.0.0\n"
    "criteriongames.com=0.0.0.0\n"
    "*.criteriongames.com=0.0.0.0\n"
    "motive-studios.com=0.0.0.0\n"
    "*.motive-studios.com=0.0.0.0\n"
    "maxis.com=0.0.0.0\n"
    "*.maxis.com=0.0.0.0\n"
    "thesims.com=0.0.0.0\n"
    "*.thesims.com=0.0.0.0\n"
    "popcap.com=0.0.0.0\n"
    "*.popcap.com=0.0.0.0\n"
    "glumobile.com=0.0.0.0\n"
    "*.glumobile.com=0.0.0.0\n"
    "playdemic.com=0.0.0.0\n"
    "*.playdemic.com=0.0.0.0\n"
    "massive.se=0.0.0.0\n"
    "*.massive.se=0.0.0.0\n"
    "redlynx.com=0.0.0.0\n"
    "*.redlynx.com=0.0.0.0\n"
    "bluemammoth.com=0.0.0.0\n"
    "*.bluemammoth.com=0.0.0.0\n"
    "brawlhalla.com=0.0.0.0\n"
    "*.brawlhalla.com=0.0.0.0\n"
    "trackmania.com=0.0.0.0\n"
    "*.trackmania.com=0.0.0.0\n"
    "anno-union.com=0.0.0.0\n"
    "*.anno-union.com=0.0.0.0\n"
    "assassinscreed.com=0.0.0.0\n"
    "*.assassinscreed.com=0.0.0.0\n"
    "justdance.com=0.0.0.0\n"
    "*.justdance.com=0.0.0.0\n"
    "farcry.com=0.0.0.0\n"
    "*.farcry.com=0.0.0.0\n"
    "thedivisiongame.com=0.0.0.0\n"
    "*.thedivisiongame.com=0.0.0.0\n"
    "wbgames.net=0.0.0.0\n"
    "*.wbgames.net=0.0.0.0\n"
    "wbagora.com=0.0.0.0\n"
    "*.wbagora.com=0.0.0.0\n"
    "netherrealm.com=0.0.0.0\n"
    "*.netherrealm.com=0.0.0.0\n"
    "mortalkombat.com=0.0.0.0\n"
    "*.mortalkombat.com=0.0.0.0\n"
    "avalanchesoftware.com=0.0.0.0\n"
    "*.avalanchesoftware.com=0.0.0.0\n"
    "portkeygames.com=0.0.0.0\n"
    "*.portkeygames.com=0.0.0.0\n"
    "hogwartslegacy.com=0.0.0.0\n"
    "*.hogwartslegacy.com=0.0.0.0\n"
    "rocksteadyltd.com=0.0.0.0\n"
    "*.rocksteadyltd.com=0.0.0.0\n"
    "multiversus.com=0.0.0.0\n"
    "*.multiversus.com=0.0.0.0\n"
    "playerfirstgames.com=0.0.0.0\n"
    "*.playerfirstgames.com=0.0.0.0\n"
    "\n"
    "# Independent and regional publishers / studios (384 additions)\n"
    "atari.com=0.0.0.0\n"
    "*.atari.com=0.0.0.0\n"
    "nightdivestudios.com=0.0.0.0\n"
    "*.nightdivestudios.com=0.0.0.0\n"
    "digitaleclipse.com=0.0.0.0\n"
    "*.digitaleclipse.com=0.0.0.0\n"
    "limitedrungames.com=0.0.0.0\n"
    "*.limitedrungames.com=0.0.0.0\n"
    "pqube.co.uk=0.0.0.0\n"
    "*.pqube.co.uk=0.0.0.0\n"
    "pqube.com=0.0.0.0\n"
    "*.pqube.com=0.0.0.0\n"
    "playism.com=0.0.0.0\n"
    "*.playism.com=0.0.0.0\n"
    "playism.jp=0.0.0.0\n"
    "*.playism.jp=0.0.0.0\n"
    "ratalaikagames.com=0.0.0.0\n"
    "*.ratalaikagames.com=0.0.0.0\n"
    "sometimesyou.com=0.0.0.0\n"
    "*.sometimesyou.com=0.0.0.0\n"
    "jandusoft.com=0.0.0.0\n"
    "*.jandusoft.com=0.0.0.0\n"
    "playway.com=0.0.0.0\n"
    "*.playway.com=0.0.0.0\n"
    "ultimate-games.com=0.0.0.0\n"
    "*.ultimate-games.com=0.0.0.0\n"
    "klabater.com=0.0.0.0\n"
    "*.klabater.com=0.0.0.0\n"
    "outrightgames.com=0.0.0.0\n"
    "*.outrightgames.com=0.0.0.0\n"
    "tophatstudios.com=0.0.0.0\n"
    "*.tophatstudios.com=0.0.0.0\n"
    "superpowerupgames.com=0.0.0.0\n"
    "*.superpowerupgames.com=0.0.0.0\n"
    "qubyteinteractive.com=0.0.0.0\n"
    "*.qubyteinteractive.com=0.0.0.0\n"
    "redartgames.com=0.0.0.0\n"
    "*.redartgames.com=0.0.0.0\n"
    "strictlylimitedgames.com=0.0.0.0\n"
    "*.strictlylimitedgames.com=0.0.0.0\n"
    "pixelheart.eu=0.0.0.0\n"
    "*.pixelheart.eu=0.0.0.0\n"
    "numskullgames.com=0.0.0.0\n"
    "*.numskullgames.com=0.0.0.0\n"
    "mergegames.com=0.0.0.0\n"
    "*.mergegames.com=0.0.0.0\n"
    "maximum-ent.com=0.0.0.0\n"
    "*.maximum-ent.com=0.0.0.0\n"
    "modusgames.com=0.0.0.0\n"
    "*.modusgames.com=0.0.0.0\n"
    "justforgames.com=0.0.0.0\n"
    "*.justforgames.com=0.0.0.0\n"
    "kepler-interactive.com=0.0.0.0\n"
    "*.kepler-interactive.com=0.0.0.0\n"
    "playstack.com=0.0.0.0\n"
    "*.playstack.com=0.0.0.0\n"
    "kwalee.com=0.0.0.0\n"
    "*.kwalee.com=0.0.0.0\n"
    "nomorerobots.io=0.0.0.0\n"
    "*.nomorerobots.io=0.0.0.0\n"
    "team17digital.com=0.0.0.0\n"
    "*.team17digital.com=0.0.0.0\n"
    "digitalbros.com=0.0.0.0\n"
    "*.digitalbros.com=0.0.0.0\n"
    "nacongaming.com=0.0.0.0\n"
    "*.nacongaming.com=0.0.0.0\n"
    "bigben.fr=0.0.0.0\n"
    "*.bigben.fr=0.0.0.0\n"
    "cyanide-studio.com=0.0.0.0\n"
    "*.cyanide-studio.com=0.0.0.0\n"
    "spiders-games.com=0.0.0.0\n"
    "*.spiders-games.com=0.0.0.0\n"
    "kt-racing.com=0.0.0.0\n"
    "*.kt-racing.com=0.0.0.0\n"
    "bigant.com=0.0.0.0\n"
    "*.bigant.com=0.0.0.0\n"
    "bigantstudios.com=0.0.0.0\n"
    "*.bigantstudios.com=0.0.0.0\n"
    "artefacts-studio.fr=0.0.0.0\n"
    "*.artefacts-studio.fr=0.0.0.0\n"
    "dont-nod.com=0.0.0.0\n"
    "*.dont-nod.com=0.0.0.0\n"
    "dontnod.com=0.0.0.0\n"
    "*.dontnod.com=0.0.0.0\n"
    "asobostudio.com=0.0.0.0\n"
    "*.asobostudio.com=0.0.0.0\n"
    "sloclap.com=0.0.0.0\n"
    "*.sloclap.com=0.0.0.0\n"
    "giants-software.com=0.0.0.0\n"
    "*.giants-software.com=0.0.0.0\n"
    "farming-simulator.com=0.0.0.0\n"
    "*.farming-simulator.com=0.0.0.0\n"
    "astragon.com=0.0.0.0\n"
    "*.astragon.com=0.0.0.0\n"
    "astragon.de=0.0.0.0\n"
    "*.astragon.de=0.0.0.0\n"
    "kalypsomedia.com=0.0.0.0\n"
    "*.kalypsomedia.com=0.0.0.0\n"
    "kalypsomedia.de=0.0.0.0\n"
    "*.kalypsomedia.de=0.0.0.0\n"
    "slitherine.com=0.0.0.0\n"
    "*.slitherine.com=0.0.0.0\n"
    "matrixgames.com=0.0.0.0\n"
    "*.matrixgames.com=0.0.0.0\n"
    "aerosoft.com=0.0.0.0\n"
    "*.aerosoft.com=0.0.0.0\n"
    "scssoft.com=0.0.0.0\n"
    "*.scssoft.com=0.0.0.0\n"
    "truckersmp.com=0.0.0.0\n"
    "*.truckersmp.com=0.0.0.0\n"
    "beamng.com=0.0.0.0\n"
    "*.beamng.com=0.0.0.0\n"
    "keenswh.com=0.0.0.0\n"
    "*.keenswh.com=0.0.0.0\n"
    "spaceengineersgame.com=0.0.0.0\n"
    "*.spaceengineersgame.com=0.0.0.0\n"
    "re-logic.com=0.0.0.0\n"
    "*.re-logic.com=0.0.0.0\n"
    "terraria.org=0.0.0.0\n"
    "*.terraria.org=0.0.0.0\n"
    "terraria.com=0.0.0.0\n"
    "*.terraria.com=0.0.0.0\n"
    "stardewvalley.net=0.0.0.0\n"
    "*.stardewvalley.net=0.0.0.0\n"
    "chucklefish.org=0.0.0.0\n"
    "*.chucklefish.org=0.0.0.0\n"
    "chucklefishgames.com=0.0.0.0\n"
    "*.chucklefishgames.com=0.0.0.0\n"
    "supergiantgames.com=0.0.0.0\n"
    "*.supergiantgames.com=0.0.0.0\n"
    "motion-twin.com=0.0.0.0\n"
    "*.motion-twin.com=0.0.0.0\n"
    "evilempirestudio.com=0.0.0.0\n"
    "*.evilempirestudio.com=0.0.0.0\n"
    "sabotagestudio.com=0.0.0.0\n"
    "*.sabotagestudio.com=0.0.0.0\n"
    "teamcherry.com.au=0.0.0.0\n"
    "*.teamcherry.com.au=0.0.0.0\n"
    "hollowknight.com=0.0.0.0\n"
    "*.hollowknight.com=0.0.0.0\n"
    "moonstudios.com=0.0.0.0\n"
    "*.moonstudios.com=0.0.0.0\n"
    "gsc-game.com=0.0.0.0\n"
    "*.gsc-game.com=0.0.0.0\n"
    "stalker2.com=0.0.0.0\n"
    "*.stalker2.com=0.0.0.0\n"
    "4a-games.com=0.0.0.0\n"
    "*.4a-games.com=0.0.0.0\n"
    "metrothegame.com=0.0.0.0\n"
    "*.metrothegame.com=0.0.0.0\n"
    "peoplecanfly.com=0.0.0.0\n"
    "*.peoplecanfly.com=0.0.0.0\n"
    "cigames.com=0.0.0.0\n"
    "*.cigames.com=0.0.0.0\n"
    "hexworks.com=0.0.0.0\n"
    "*.hexworks.com=0.0.0.0\n"
    "lordsofthefallen.com=0.0.0.0\n"
    "*.lordsofthefallen.com=0.0.0.0\n"
    "blooberteam.com=0.0.0.0\n"
    "*.blooberteam.com=0.0.0.0\n"
    "blooberteam.pl=0.0.0.0\n"
    "*.blooberteam.pl=0.0.0.0\n"
    "frozendistrict.com=0.0.0.0\n"
    "*.frozendistrict.com=0.0.0.0\n"
    "houseflippergame.com=0.0.0.0\n"
    "*.houseflippergame.com=0.0.0.0\n"
    "tensquaregames.com=0.0.0.0\n"
    "*.tensquaregames.com=0.0.0.0\n"
    "artifexmundi.com=0.0.0.0\n"
    "*.artifexmundi.com=0.0.0.0\n"
    "herocraft.com=0.0.0.0\n"
    "*.herocraft.com=0.0.0.0\n"
    "alawar.com=0.0.0.0\n"
    "*.alawar.com=0.0.0.0\n"
    "alawar.ru=0.0.0.0\n"
    "*.alawar.ru=0.0.0.0\n"
    "nicalis.com=0.0.0.0\n"
    "*.nicalis.com=0.0.0.0\n"
    "nighthawkinteractive.com=0.0.0.0\n"
    "*.nighthawkinteractive.com=0.0.0.0\n"
    "pm-studios.com=0.0.0.0\n"
    "*.pm-studios.com=0.0.0.0\n"
    "pmstudios.com=0.0.0.0\n"
    "*.pmstudios.com=0.0.0.0\n"
    "headupgames.com=0.0.0.0\n"
    "*.headupgames.com=0.0.0.0\n"
    "headupgames.de=0.0.0.0\n"
    "*.headupgames.de=0.0.0.0\n"
    "untoldtales.games=0.0.0.0\n"
    "*.untoldtales.games=0.0.0.0\n"
    "neondoctrine.com=0.0.0.0\n"
    "*.neondoctrine.com=0.0.0.0\n"
    "whitethorngames.com=0.0.0.0\n"
    "*.whitethorngames.com=0.0.0.0\n"
    "fellowtraveller.games=0.0.0.0\n"
    "*.fellowtraveller.games=0.0.0.0\n"
    "thunderfulgames.com=0.0.0.0\n"
    "*.thunderfulgames.com=0.0.0.0\n"
    "thunderfulgroup.com=0.0.0.0\n"
    "*.thunderfulgroup.com=0.0.0.0\n"
    "imageform.se=0.0.0.0\n"
    "*.imageform.se=0.0.0.0\n"
    "risingstargames.com=0.0.0.0\n"
    "*.risingstargames.com=0.0.0.0\n"
    "armorgames.com=0.0.0.0\n"
    "*.armorgames.com=0.0.0.0\n"
    "newgrounds.com=0.0.0.0\n"
    "*.newgrounds.com=0.0.0.0\n"
    "kongregate.com=0.0.0.0\n"
    "*.kongregate.com=0.0.0.0\n"
    "miniclip.com=0.0.0.0\n"
    "*.miniclip.com=0.0.0.0\n"
    "gameloft.com=0.0.0.0\n"
    "*.gameloft.com=0.0.0.0\n"
    "gameloft.org=0.0.0.0\n"
    "*.gameloft.org=0.0.0.0\n"
    "scopely.com=0.0.0.0\n"
    "*.scopely.com=0.0.0.0\n"
    "scopely.io=0.0.0.0\n"
    "*.scopely.io=0.0.0.0\n"
    "monopolygo.com=0.0.0.0\n"
    "*.monopolygo.com=0.0.0.0\n"
    "niantic.com=0.0.0.0\n"
    "*.niantic.com=0.0.0.0\n"
    "playrix.com=0.0.0.0\n"
    "*.playrix.com=0.0.0.0\n"
    "playrix.net=0.0.0.0\n"
    "*.playrix.net=0.0.0.0\n"
    "dreamgames.com=0.0.0.0\n"
    "*.dreamgames.com=0.0.0.0\n"
    "royalmatch.com=0.0.0.0\n"
    "*.royalmatch.com=0.0.0.0\n"
    "lilithgames.com=0.0.0.0\n"
    "*.lilithgames.com=0.0.0.0\n"
    "igg.com=0.0.0.0\n"
    "*.igg.com=0.0.0.0\n"
    "igg.net=0.0.0.0\n"
    "*.igg.net=0.0.0.0\n"
    "funplus.com=0.0.0.0\n"
    "*.funplus.com=0.0.0.0\n"
    "funplusgames.com=0.0.0.0\n"
    "*.funplusgames.com=0.0.0.0\n"
    "yostar.com=0.0.0.0\n"
    "*.yostar.com=0.0.0.0\n"
    "yostar.co.jp=0.0.0.0\n"
    "*.yostar.co.jp=0.0.0.0\n"
    "yo-star.com=0.0.0.0\n"
    "*.yo-star.com=0.0.0.0\n"
    "hypergryph.com=0.0.0.0\n"
    "*.hypergryph.com=0.0.0.0\n"
    "arknights.global=0.0.0.0\n"
    "*.arknights.global=0.0.0.0\n"
    "arknights.com=0.0.0.0\n"
    "*.arknights.com=0.0.0.0\n"
    "gryphline.com=0.0.0.0\n"
    "*.gryphline.com=0.0.0.0\n"
    "sunborn.com=0.0.0.0\n"
    "*.sunborn.com=0.0.0.0\n"
    "girlsfrontline.com=0.0.0.0\n"
    "*.girlsfrontline.com=0.0.0.0\n"
    "papegames.com=0.0.0.0\n"
    "*.papegames.com=0.0.0.0\n"
    "infoldgames.com=0.0.0.0\n"
    "*.infoldgames.com=0.0.0.0\n"
    "infinitynikki.com=0.0.0.0\n"
    "*.infinitynikki.com=0.0.0.0\n"
    "loveanddeepspace.com=0.0.0.0\n"
    "*.loveanddeepspace.com=0.0.0.0\n"
    "bilibiligame.com=0.0.0.0\n"
    "*.bilibiligame.com=0.0.0.0\n"
    "biligame.com=0.0.0.0\n"
    "*.biligame.com=0.0.0.0\n"
    "taptap.com=0.0.0.0\n"
    "*.taptap.com=0.0.0.0\n"
    "taptap.cn=0.0.0.0\n"
    "*.taptap.cn=0.0.0.0\n"
    "heartmachine.com=0.0.0.0\n"
    "*.heartmachine.com=0.0.0.0\n"
    "thatgamecompany.com=0.0.0.0\n"
    "*.thatgamecompany.com=0.0.0.0\n"
    "skychildrenofthelight.com=0.0.0.0\n"
    "*.skychildrenofthelight.com=0.0.0.0\n"
    "mobiusdigitalgames.com=0.0.0.0\n"
    "*.mobiusdigitalgames.com=0.0.0.0\n"
    "outerwilds.com=0.0.0.0\n"
    "*.outerwilds.com=0.0.0.0\n"
    "unknownworlds.com=0.0.0.0\n"
    "*.unknownworlds.com=0.0.0.0\n"
    "subnautica.com=0.0.0.0\n"
    "*.subnautica.com=0.0.0.0\n"
    "irongatestudio.se=0.0.0.0\n"
    "*.irongatestudio.se=0.0.0.0\n"
    "valheimgame.com=0.0.0.0\n"
    "*.valheimgame.com=0.0.0.0\n"
    "studiowildcard.com=0.0.0.0\n"
    "*.studiowildcard.com=0.0.0.0\n"
    "survivetheark.com=0.0.0.0\n"
    "*.survivetheark.com=0.0.0.0\n"
    "playark.com=0.0.0.0\n"
    "*.playark.com=0.0.0.0\n"
    "snailgamesusa.com=0.0.0.0\n"
    "*.snailgamesusa.com=0.0.0.0\n"
    "snailgames.com=0.0.0.0\n"
    "*.snailgames.com=0.0.0.0\n"
    "pocketpair.jp=0.0.0.0\n"
    "*.pocketpair.jp=0.0.0.0\n"
    "palworldgame.com=0.0.0.0\n"
    "*.palworldgame.com=0.0.0.0\n"
    "satisfactorygame.com=0.0.0.0\n"
    "*.satisfactorygame.com=0.0.0.0\n"
    "tripwireinteractive.com=0.0.0.0\n"
    "*.tripwireinteractive.com=0.0.0.0\n"
    "killingfloor2.com=0.0.0.0\n"
    "*.killingfloor2.com=0.0.0.0\n"
    "tornbanner.com=0.0.0.0\n"
    "*.tornbanner.com=0.0.0.0\n"
    "chivalry2.com=0.0.0.0\n"
    "*.chivalry2.com=0.0.0.0\n"
    "irongalaxystudios.com=0.0.0.0\n"
    "*.irongalaxystudios.com=0.0.0.0\n"
    "guninteractive.com=0.0.0.0\n"
    "*.guninteractive.com=0.0.0.0\n"
    "txchainsawgame.com=0.0.0.0\n"
    "*.txchainsawgame.com=0.0.0.0\n"
    "sumo-digital.com=0.0.0.0\n"
    "*.sumo-digital.com=0.0.0.0\n"
    "sumogroupplc.com=0.0.0.0\n"
    "*.sumogroupplc.com=0.0.0.0\n"
    "secretmode.games=0.0.0.0\n"
    "*.secretmode.games=0.0.0.0\n"
    "rebellion.com=0.0.0.0\n"
    "*.rebellion.com=0.0.0.0\n"
    "rebellion.co.uk=0.0.0.0\n"
    "*.rebellion.co.uk=0.0.0.0\n"
    "sniperelite.com=0.0.0.0\n"
    "*.sniperelite.com=0.0.0.0\n"
    "d3t.co.uk=0.0.0.0\n"
    "*.d3t.co.uk=0.0.0.0\n"
    "double11.com=0.0.0.0\n"
    "*.double11.com=0.0.0.0\n"
    "doubleeleven.com=0.0.0.0\n"
    "*.doubleeleven.com=0.0.0.0\n"
    "splashdamage.com=0.0.0.0\n"
    "*.splashdamage.com=0.0.0.0\n"
    "supermassivegames.com=0.0.0.0\n"
    "*.supermassivegames.com=0.0.0.0\n"
    "darkpictures.com=0.0.0.0\n"
    "*.darkpictures.com=0.0.0.0\n"
    "steelwoolstudios.com=0.0.0.0\n"
    "*.steelwoolstudios.com=0.0.0.0\n"
    "steelwoolgames.com=0.0.0.0\n"
    "*.steelwoolgames.com=0.0.0.0\n"
    "scottgames.com=0.0.0.0\n"
    "*.scottgames.com=0.0.0.0\n"
    "mobentertainment.com=0.0.0.0\n"
    "*.mobentertainment.com=0.0.0.0\n"
    "poppyplaytime.com=0.0.0.0\n"
    "*.poppyplaytime.com=0.0.0.0\n"
    "kineticgames.co.uk=0.0.0.0\n"
    "*.kineticgames.co.uk=0.0.0.0\n"
    "phasmophobia.com=0.0.0.0\n"
    "*.phasmophobia.com=0.0.0.0\n"
    "innersloth.com=0.0.0.0\n"
    "*.innersloth.com=0.0.0.0\n"
    "amongus.com=0.0.0.0\n"
    "*.amongus.com=0.0.0.0\n"
    "mediatonicgames.com=0.0.0.0\n"
    "*.mediatonicgames.com=0.0.0.0\n"
    "hellogames.org=0.0.0.0\n"
    "*.hellogames.org=0.0.0.0\n"
    "nomanssky.com=0.0.0.0\n"
    "*.nomanssky.com=0.0.0.0\n"
    "frontier.co.uk=0.0.0.0\n"
    "*.frontier.co.uk=0.0.0.0\n"
    "frontierdevelopments.com=0.0.0.0\n"
    "*.frontierdevelopments.com=0.0.0.0\n"
    "elitedangerous.com=0.0.0.0\n"
    "*.elitedangerous.com=0.0.0.0\n"
    "jurassicworldevolution.com=0.0.0.0\n"
    "*.jurassicworldevolution.com=0.0.0.0\n"
    "planetcoaster.com=0.0.0.0\n"
    "*.planetcoaster.com=0.0.0.0\n"
    "planetzoogame.com=0.0.0.0\n"
    "*.planetzoogame.com=0.0.0.0\n"
    "\n"
    "# Dedicated online middleware and gaming services (68 additions)\n"
    "battleye.com=0.0.0.0\n"
    "*.battleye.com=0.0.0.0\n"
    "punkbuster.com=0.0.0.0\n"
    "*.punkbuster.com=0.0.0.0\n"
    "evenbalance.com=0.0.0.0\n"
    "*.evenbalance.com=0.0.0.0\n"
    "gamespy.com=0.0.0.0\n"
    "*.gamespy.com=0.0.0.0\n"
    "gamesparks.com=0.0.0.0\n"
    "*.gamesparks.com=0.0.0.0\n"
    "gamesparks.net=0.0.0.0\n"
    "*.gamesparks.net=0.0.0.0\n"
    "photonengine.com=0.0.0.0\n"
    "*.photonengine.com=0.0.0.0\n"
    "exitgames.com=0.0.0.0\n"
    "*.exitgames.com=0.0.0.0\n"
    "photoncloud.com=0.0.0.0\n"
    "*.photoncloud.com=0.0.0.0\n"
    "vivox.com=0.0.0.0\n"
    "*.vivox.com=0.0.0.0\n"
    "vivox.net=0.0.0.0\n"
    "*.vivox.net=0.0.0.0\n"
    "accelbyte.io=0.0.0.0\n"
    "*.accelbyte.io=0.0.0.0\n"
    "pragma.gg=0.0.0.0\n"
    "*.pragma.gg=0.0.0.0\n"
    "heroiclabs.com=0.0.0.0\n"
    "*.heroiclabs.com=0.0.0.0\n"
    "mod.io=0.0.0.0\n"
    "*.mod.io=0.0.0.0\n"
    "modio.com=0.0.0.0\n"
    "*.modio.com=0.0.0.0\n"
    "gameanalytics.com=0.0.0.0\n"
    "*.gameanalytics.com=0.0.0.0\n"
    "gameanalytics.io=0.0.0.0\n"
    "*.gameanalytics.io=0.0.0.0\n"
    "deltadna.net=0.0.0.0\n"
    "*.deltadna.net=0.0.0.0\n"
    "deltadna.com=0.0.0.0\n"
    "*.deltadna.com=0.0.0.0\n"
    "gamesight.io=0.0.0.0\n"
    "*.gamesight.io=0.0.0.0\n"
    "gameye.com=0.0.0.0\n"
    "*.gameye.com=0.0.0.0\n"
    "edgegap.com=0.0.0.0\n"
    "*.edgegap.com=0.0.0.0\n"
    "geforcenow.com=0.0.0.0\n"
    "*.geforcenow.com=0.0.0.0\n"
    "boosteroid.com=0.0.0.0\n"
    "*.boosteroid.com=0.0.0.0\n"
    "blacknut.com=0.0.0.0\n"
    "*.blacknut.com=0.0.0.0\n"
    "luna.amazon.com=0.0.0.0\n"
    "*.luna.amazon.com=0.0.0.0\n"
    "oculus.com=0.0.0.0\n"
    "*.oculus.com=0.0.0.0\n"
    "oculuscdn.com=0.0.0.0\n"
    "*.oculuscdn.com=0.0.0.0\n"
    "metaquest.com=0.0.0.0\n"
    "*.metaquest.com=0.0.0.0\n"
    "vive.com=0.0.0.0\n"
    "*.vive.com=0.0.0.0\n"
    "viveport.com=0.0.0.0\n"
    "*.viveport.com=0.0.0.0\n"
    "pico-interactive.com=0.0.0.0\n"
    "*.pico-interactive.com=0.0.0.0\n"
    "picoxr.com=0.0.0.0\n"
    "*.picoxr.com=0.0.0.0\n"
    "\n"
    "# Verified network families and dedicated aliases (Steam support, Riot support, PlayVS and public DNS inventories)\n"
    "pvp.net=0.0.0.0\n"
    "*.pvp.net=0.0.0.0\n"
    "riotgamespatcher-a.akamaihd.net=0.0.0.0\n"
    "*.riotgamespatcher-a.akamaihd.net=0.0.0.0\n"
    "game.qq.com=0.0.0.0\n"
    "*.game.qq.com=0.0.0.0\n"
    "tdm.qq.com=0.0.0.0\n"
    "*.tdm.qq.com=0.0.0.0\n"
    "\n"
    "# Additional publisher and studio candidates from PS4/PS5 catalogues and multi-platform inventory\n"
    "garena.com=0.0.0.0\n"
    "*.garena.com=0.0.0.0\n"
    "garena.sg=0.0.0.0\n"
    "*.garena.sg=0.0.0.0\n"
    "garena.vn=0.0.0.0\n"
    "*.garena.vn=0.0.0.0\n"
    "garena.tw=0.0.0.0\n"
    "*.garena.tw=0.0.0.0\n"
    "freefire.com=0.0.0.0\n"
    "*.freefire.com=0.0.0.0\n"
    "freefiremobile.com=0.0.0.0\n"
    "*.freefiremobile.com=0.0.0.0\n"
    "gameforge.com=0.0.0.0\n"
    "*.gameforge.com=0.0.0.0\n"
    "gameforge.de=0.0.0.0\n"
    "*.gameforge.de=0.0.0.0\n"
    "gameforge.net=0.0.0.0\n"
    "*.gameforge.net=0.0.0.0\n"
    "aiononline.com=0.0.0.0\n"
    "*.aiononline.com=0.0.0.0\n"
    "lineage2.com=0.0.0.0\n"
    "*.lineage2.com=0.0.0.0\n"
    "ncamerica.com=0.0.0.0\n"
    "*.ncamerica.com=0.0.0.0\n"
    "hoodedhorse.com=0.0.0.0\n"
    "*.hoodedhorse.com=0.0.0.0\n"
    "fulqrumpublishing.com=0.0.0.0\n"
    "*.fulqrumpublishing.com=0.0.0.0\n"
    "1cpublishing.eu=0.0.0.0\n"
    "*.1cpublishing.eu=0.0.0.0\n"
    "superraregames.com=0.0.0.0\n"
    "*.superraregames.com=0.0.0.0\n"
    "ripstone.com=0.0.0.0\n"
    "*.ripstone.com=0.0.0.0\n"
    "resolutiongames.com=0.0.0.0\n"
    "*.resolutiongames.com=0.0.0.0\n"
    "survios.com=0.0.0.0\n"
    "*.survios.com=0.0.0.0\n"
    "squanchgames.com=0.0.0.0\n"
    "*.squanchgames.com=0.0.0.0\n"
    "joeydrewstudios.com=0.0.0.0\n"
    "*.joeydrewstudios.com=0.0.0.0\n"
    "sunblink.com=0.0.0.0\n"
    "*.sunblink.com=0.0.0.0\n"
    "weakfishstudio.com=0.0.0.0\n"
    "*.weakfishstudio.com=0.0.0.0\n"
    "meridiem-games.com=0.0.0.0\n"
    "*.meridiem-games.com=0.0.0.0\n"
    "avalanche-studios.com=0.0.0.0\n"
    "*.avalanche-studios.com=0.0.0.0\n"
    "avalanchestudios.com=0.0.0.0\n"
    "*.avalanchestudios.com=0.0.0.0\n"
    "destructivecreations.com=0.0.0.0\n"
    "*.destructivecreations.com=0.0.0.0\n"
    "ehomegames.com=0.0.0.0\n"
    "*.ehomegames.com=0.0.0.0\n"
    "gamesincubator.com=0.0.0.0\n"
    "*.gamesincubator.com=0.0.0.0\n"
    "blitworks.com=0.0.0.0\n"
    "*.blitworks.com=0.0.0.0\n"
    "cfk.kr=0.0.0.0\n"
    "*.cfk.kr=0.0.0.0\n"
    "skystone.games=0.0.0.0\n"
    "*.skystone.games=0.0.0.0\n"
    "monster-games.com=0.0.0.0\n"
    "*.monster-games.com=0.0.0.0\n"
    "pix-arts.com=0.0.0.0\n"
    "*.pix-arts.com=0.0.0.0\n"
    "oceanmedia.hr=0.0.0.0\n"
    "*.oceanmedia.hr=0.0.0.0\n"
    "entergram.co.jp=0.0.0.0\n"
    "*.entergram.co.jp=0.0.0.0\n"
    "lightwoodgames.com=0.0.0.0\n"
    "*.lightwoodgames.com=0.0.0.0\n"
    "lillymogames.com=0.0.0.0\n"
    "*.lillymogames.com=0.0.0.0\n"
    "anvilstudios.com=0.0.0.0\n"
    "*.anvilstudios.com=0.0.0.0\n"
    "synnergycirclegames.com=0.0.0.0\n"
    "*.synnergycirclegames.com=0.0.0.0\n"
    "digitalcybercherries.com=0.0.0.0\n"
    "*.digitalcybercherries.com=0.0.0.0\n"
    "hyperchargegame.com=0.0.0.0\n"
    "*.hyperchargegame.com=0.0.0.0\n"
    "grip-digital.com=0.0.0.0\n"
    "*.grip-digital.com=0.0.0.0\n"
    "wiredproductions.com=0.0.0.0\n"
    "*.wiredproductions.com=0.0.0.0\n"
    "ustwogames.co.uk=0.0.0.0\n"
    "*.ustwogames.co.uk=0.0.0.0\n"
    "redhookstudios.com=0.0.0.0\n"
    "*.redhookstudios.com=0.0.0.0\n"
    "darkestdungeon.com=0.0.0.0\n"
    "*.darkestdungeon.com=0.0.0.0\n"
    "nightdive.com=0.0.0.0\n"
    "*.nightdive.com=0.0.0.0\n"
    "rainmakerproductions.com=0.0.0.0\n"
    "*.rainmakerproductions.com=0.0.0.0\n"
    "iam8bit.com=0.0.0.0\n"
    "*.iam8bit.com=0.0.0.0\n"
    "shepherd.games=0.0.0.0\n"
    "*.shepherd.games=0.0.0.0\n"
    "goodshepherd.games=0.0.0.0\n"
    "*.goodshepherd.games=0.0.0.0\n"
    "rawthrills.com=0.0.0.0\n"
    "*.rawthrills.com=0.0.0.0\n"
    "thalamusdigital.com=0.0.0.0\n"
    "*.thalamusdigital.com=0.0.0.0\n"
    "curve-digital.com=0.0.0.0\n"
    "*.curve-digital.com=0.0.0.0\n"
    "firesidegames.com=0.0.0.0\n"
    "*.firesidegames.com=0.0.0.0\n"
    "2awesome.studio=0.0.0.0\n"
    "*.2awesome.studio=0.0.0.0\n"
    "superrare.games=0.0.0.0\n"
    "*.superrare.games=0.0.0.0\n"
    "hitcents.com=0.0.0.0\n"
    "*.hitcents.com=0.0.0.0\n"
    "team-reptile.com=0.0.0.0\n"
    "*.team-reptile.com=0.0.0.0\n"
    "teamreptile.com=0.0.0.0\n"
    "*.teamreptile.com=0.0.0.0\n"
    "noxcrew.com=0.0.0.0\n"
    "*.noxcrew.com=0.0.0.0\n"
    "tinybuildgames.com=0.0.0.0\n"
    "*.tinybuildgames.com=0.0.0.0\n"
    "snowcastle.games=0.0.0.0\n"
    "*.snowcastle.games=0.0.0.0\n"
    "snowcastlegames.com=0.0.0.0\n"
    "*.snowcastlegames.com=0.0.0.0\n"
    "inin.games=0.0.0.0\n"
    "*.inin.games=0.0.0.0\n"
    "unitedgames-entertainment.com=0.0.0.0\n"
    "*.unitedgames-entertainment.com=0.0.0.0\n"
    "justdan.com=0.0.0.0\n"
    "*.justdan.com=0.0.0.0\n"
    "justdan.com.tw=0.0.0.0\n"
    "*.justdan.com.tw=0.0.0.0\n"
    "redgames.co=0.0.0.0\n"
    "*.redgames.co=0.0.0.0\n"
    "redgamesco.com=0.0.0.0\n"
    "*.redgamesco.com=0.0.0.0\n"
    "zenstudios.com=0.0.0.0\n"
    "*.zenstudios.com=0.0.0.0\n"
    "frozenbyte.com=0.0.0.0\n"
    "*.frozenbyte.com=0.0.0.0\n"
    "frogwares.com=0.0.0.0\n"
    "*.frogwares.com=0.0.0.0\n"
    "madheadgames.com=0.0.0.0\n"
    "*.madheadgames.com=0.0.0.0\n"
    "stormindgames.com=0.0.0.0\n"
    "*.stormindgames.com=0.0.0.0\n"
    "blackforestgames.com=0.0.0.0\n"
    "*.blackforestgames.com=0.0.0.0\n"
    "mimimi.games=0.0.0.0\n"
    "*.mimimi.games=0.0.0.0\n"
    "ic.com=0.0.0.0\n"
    "*.ic.com=0.0.0.0\n"
    "daedalic.com=0.0.0.0\n"
    "*.daedalic.com=0.0.0.0\n"
    "deck13.com=0.0.0.0\n"
    "*.deck13.com=0.0.0.0\n"
    "deck13.de=0.0.0.0\n"
    "*.deck13.de=0.0.0.0\n"
    "deck13spotlight.com=0.0.0.0\n"
    "*.deck13spotlight.com=0.0.0.0\n"
    "runningwithscissors.com=0.0.0.0\n"
    "*.runningwithscissors.com=0.0.0.0\n"
    "postal.game=0.0.0.0\n"
    "*.postal.game=0.0.0.0\n"
    "\n"
    "# Additional online-first franchises and middleware candidates\n"
    "pathofexile.com=0.0.0.0\n"
    "*.pathofexile.com=0.0.0.0\n"
    "grindinggear.com=0.0.0.0\n"
    "*.grindinggear.com=0.0.0.0\n"
    "grindinggear.games=0.0.0.0\n"
    "*.grindinggear.games=0.0.0.0\n"
    "pathofexile2.com=0.0.0.0\n"
    "*.pathofexile2.com=0.0.0.0\n"
    "eadp.net=0.0.0.0\n"
    "*.eadp.net=0.0.0.0\n"
    "warface.com=0.0.0.0\n"
    "*.warface.com=0.0.0.0\n"
    "paladins.com=0.0.0.0\n"
    "*.paladins.com=0.0.0.0\n"
    "roguecompany.com=0.0.0.0\n"
    "*.roguecompany.com=0.0.0.0\n"
    "smite2.com=0.0.0.0\n"
    "*.smite2.com=0.0.0.0\n"
    "hirez.com=0.0.0.0\n"
    "*.hirez.com=0.0.0.0\n"
    "rainbow6.com=0.0.0.0\n"
    "*.rainbow6.com=0.0.0.0\n"
    "turtlerockstudios.com=0.0.0.0\n"
    "*.turtlerockstudios.com=0.0.0.0\n"
    "back4blood.com=0.0.0.0\n"
    "*.back4blood.com=0.0.0.0\n"
    "left4dead.com=0.0.0.0\n"
    "*.left4dead.com=0.0.0.0\n"
    "counter-strike.net=0.0.0.0\n"
    "*.counter-strike.net=0.0.0.0\n"
    "dota2.com=0.0.0.0\n"
    "*.dota2.com=0.0.0.0\n"
    "teamfortress.com=0.0.0.0\n"
    "*.teamfortress.com=0.0.0.0\n"
    "half-life.com=0.0.0.0\n"
    "*.half-life.com=0.0.0.0\n"
    "steamchina.com=0.0.0.0\n"
    "*.steamchina.com=0.0.0.0\n"
    "steamchina.com.cn=0.0.0.0\n"
    "*.steamchina.com.cn=0.0.0.0\n"
    "riftgame.com=0.0.0.0\n"
    "*.riftgame.com=0.0.0.0\n"
    "trionworlds.com=0.0.0.0\n"
    "*.trionworlds.com=0.0.0.0\n"
    "gamigo.com=0.0.0.0\n"
    "*.gamigo.com=0.0.0.0\n"
    "gamigo.net=0.0.0.0\n"
    "*.gamigo.net=0.0.0.0\n"
    "glyph.net=0.0.0.0\n"
    "*.glyph.net=0.0.0.0\n"
    "archeage.com=0.0.0.0\n"
    "*.archeage.com=0.0.0.0\n"
    "unitygamingservices.com=0.0.0.0\n"
    "*.unitygamingservices.com=0.0.0.0\n"
    "cloud.unity3d.com=0.0.0.0\n"
    "*.cloud.unity3d.com=0.0.0.0\n"
    "services.unity.com=0.0.0.0\n"
    "*.services.unity.com=0.0.0.0\n"
    "relay.unity3d.com=0.0.0.0\n"
    "*.relay.unity3d.com=0.0.0.0\n"
    "matchmaker.unity3d.com=0.0.0.0\n"
    "*.matchmaker.unity3d.com=0.0.0.0\n"
    "unityads.unity3d.com=0.0.0.0\n"
    "*.unityads.unity3d.com=0.0.0.0\n"
    "ads.unity.com=0.0.0.0\n"
    "*.ads.unity.com=0.0.0.0\n"
    "unityads.com=0.0.0.0\n"
    "*.unityads.com=0.0.0.0\n"
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
    "scsi-upload-lp1.s3.us-west-2.amazonaws.com",
    "rocketleague.com",
    "psyonix.com",
    "fallguys.com",
    "codemasters.com",
    "microsoft.com",
    "minecraft.net",
    "minecraftservices.com",
    "mojang.com",
    "atlus.co.jp",
    "capcom.co.jp",
    "square-enix-games.com",
    "square-enix.co.jp",
    "fromsoftware.jp",
    "konami.com",
    "konami.net",
    "yugioh-card.com",
    "activision.com",
    "callofduty.com",
    "demonware.net",
    "demonware.com",
    "blizzard.com",
    "battle.net",
    "bethesda.net",
    "bethesda.com",
    "zenimax.com",
    "gearboxsoftware.com",
    "wbgames.com",
    "wbplay.com",
    "warnerbrosgames.com",
    "ttgames.com",
    "koeitecmo.com",
    "koeitecmoamerica.com",
    "koeitecmo.co.jp",
    "gamecity.ne.jp",
    "level5.co.jp",
    "marvelous.co.jp",
    "nisamerica.com",
    "nippon1.co.jp",
    "spike-chunsoft.com",
    "spike-chunsoft.co.jp",
    "arcsystemworks.com",
    "arcsygames.com",
    "inticreates.com",
    "gungho.jp",
    "505games.com",
    "team17.com",
    "thqnordic.com",
    "plaion.com",
    "deep-silver.com",
    "tinybuild.com",
    "devolverdigital.com",
    "nacon.com",
    "maximumgames.com",
    "rawfury.com",
    "annapurnainteractive.com",
    "humblegames.com",
    "curvegames.com",
    "dotemu.com",
    "microids.com",
    "telltale.com",
    "jackboxgames.com",
    "jackbox.tv",
    "playdigious.com",
    "warframe.com",
    "digitalextremes.com",
    "deadbydaylight.com",
    "bhvr.com",
    "hirezstudios.com",
    "smitegame.com",
    "pokemon.com",
    "pokemon.co.jp",
    "pokemonunite.com",
    "*.rocketleague.com",
    "*.psyonix.com",
    "*.fallguys.com",
    "*.codemasters.com",
    "*.minecraft.net",
    "*.minecraftservices.com",
    "*.mojang.com",
    "*.atlus.co.jp",
    "*.capcom.co.jp",
    "*.square-enix-games.com",
    "*.square-enix.co.jp",
    "*.fromsoftware.jp",
    "*.konami.com",
    "*.konami.net",
    "*.yugioh-card.com",
    "*.activision.com",
    "*.callofduty.com",
    "*.demonware.net",
    "*.demonware.com",
    "*.blizzard.com",
    "*.battle.net",
    "*.bethesda.net",
    "*.bethesda.com",
    "*.zenimax.com",
    "*.gearboxsoftware.com",
    "*.phoenix-api.wbagora.com",
    "*.wbgames.com",
    "*.wbplay.com",
    "*.warnerbrosgames.com",
    "*.ttgames.com",
    "*.koeitecmo.com",
    "*.koeitecmoamerica.com",
    "*.koeitecmo.co.jp",
    "*.gamecity.ne.jp",
    "*.level5.co.jp",
    "*.marvelous.co.jp",
    "*.nisamerica.com",
    "*.nippon1.co.jp",
    "*.spike-chunsoft.com",
    "*.spike-chunsoft.co.jp",
    "*.arcsystemworks.com",
    "*.arcsygames.com",
    "*.inticreates.com",
    "*.gungho.jp",
    "*.505games.com",
    "*.team17.com",
    "*.thqnordic.com",
    "*.plaion.com",
    "*.deep-silver.com",
    "*.tinybuild.com",
    "*.devolverdigital.com",
    "*.nacon.com",
    "*.maximumgames.com",
    "*.rawfury.com",
    "*.annapurnainteractive.com",
    "*.humblegames.com",
    "*.curvegames.com",
    "*.dotemu.com",
    "*.microids.com",
    "*.telltale.com",
    "*.jackboxgames.com",
    "*.jackbox.tv",
    "*.playdigious.com",
    "*.warframe.com",
    "*.digitalextremes.com",
    "*.deadbydaylight.com",
    "*.bhvr.com",
    "*.hirezstudios.com",
    "*.smitegame.com",
    "*.pokemon.com",
    "*.pokemon.co.jp",
    "*.pokemonunite.com",
    "steamgames.com",
    "*.steamgames.com",
    "steamstatic.com",
    "*.steamstatic.com",
    "steamcontent.com",
    "*.steamcontent.com",
    "steamserver.net",
    "*.steamserver.net",
    "steamusercontent.com",
    "*.steamusercontent.com",
    "steamdeck.com",
    "*.steamdeck.com",
    "steambroadcast.com",
    "*.steambroadcast.com",
    "steam-chat.com",
    "*.steam-chat.com",
    "steam.tv",
    "*.steam.tv",
    "xboxgamepass.com",
    "*.xboxgamepass.com",
    "xboxstudios.com",
    "*.xboxstudios.com",
    "playfabapi.com",
    "*.playfabapi.com",
    "playfab.com",
    "*.playfab.com",
    "humblebundle.com",
    "*.humblebundle.com",
    "epicgames-download1.akamaized.net",
    "*.epicgames-download1.akamaized.net",
    "epicgames-download2.akamaized.net",
    "*.epicgames-download2.akamaized.net",
    "eaassets-a.akamaihd.net",
    "*.eaassets-a.akamaihd.net",
    "origin-a.akamaihd.net",
    "*.origin-a.akamaihd.net",
    "ubistatic.com",
    "*.ubistatic.com",
    "ubistatic2-a.akamaihd.net",
    "*.ubistatic2-a.akamaihd.net",
    "bungie.net",
    "*.bungie.net",
    "bungie.com",
    "*.bungie.com",
    "destinythegame.com",
    "*.destinythegame.com",
    "naughtydog.com",
    "*.naughtydog.com",
    "insomniac.games",
    "*.insomniac.games",
    "guerrilla-games.com",
    "*.guerrilla-games.com",
    "santamonicastudio.com",
    "*.santamonicastudio.com",
    "suckerpunch.com",
    "*.suckerpunch.com",
    "bendstudio.com",
    "*.bendstudio.com",
    "polyphony.co.jp",
    "*.polyphony.co.jp",
    "gran-turismo.com",
    "*.gran-turismo.com",
    "housemarque.com",
    "*.housemarque.com",
    "firesprite.com",
    "*.firesprite.com",
    "bluepointgames.com",
    "*.bluepointgames.com",
    "mediamolecule.com",
    "*.mediamolecule.com",
    "havenstudios.com",
    "*.havenstudios.com",
    "arrowheadgamestudios.com",
    "*.arrowheadgamestudios.com",
    "helldivers.com",
    "*.helldivers.com",
    "kojimaproductions.jp",
    "*.kojimaproductions.jp",
    "quanticdream.com",
    "*.quanticdream.com",
    "shiftup.co.kr",
    "*.shiftup.co.kr",
    "stellarblade.com",
    "*.stellarblade.com",
    "riotgames.com",
    "*.riotgames.com",
    "riotgames.net",
    "*.riotgames.net",
    "riotcdn.net",
    "*.riotcdn.net",
    "leagueoflegends.com",
    "*.leagueoflegends.com",
    "playvalorant.com",
    "*.playvalorant.com",
    "valorant.com",
    "*.valorant.com",
    "teamfighttactics.com",
    "*.teamfighttactics.com",
    "lolesports.com",
    "*.lolesports.com",
    "netease.com",
    "*.netease.com",
    "neteasegames.com",
    "*.neteasegames.com",
    "marvelrivals.com",
    "*.marvelrivals.com",
    "wherewindsmeetgame.com",
    "*.wherewindsmeetgame.com",
    "oncehuman.game",
    "*.oncehuman.game",
    "identityvgame.com",
    "*.identityvgame.com",
    "narakabladepoint.com",
    "*.narakabladepoint.com",
    "tencentgames.com",
    "*.tencentgames.com",
    "levelinfinite.com",
    "*.levelinfinite.com",
    "lightspeed-studios.com",
    "*.lightspeed-studios.com",
    "timistudios.com",
    "*.timistudios.com",
    "pubg.com",
    "*.pubg.com",
    "pubgmobile.com",
    "*.pubgmobile.com",
    "krafton.com",
    "*.krafton.com",
    "playbattlegrounds.com",
    "*.playbattlegrounds.com",
    "nexon.com",
    "*.nexon.com",
    "nexon.net",
    "*.nexon.net",
    "nexon.co.jp",
    "*.nexon.co.jp",
    "maplestory.com",
    "*.maplestory.com",
    "dungeonfighteronline.com",
    "*.dungeonfighteronline.com",
    "neople.co.kr",
    "*.neople.co.kr",
    "pearlabyss.com",
    "*.pearlabyss.com",
    "playblackdesert.com",
    "*.playblackdesert.com",
    "blackdesertonline.com",
    "*.blackdesertonline.com",
    "crimsondesert.com",
    "*.crimsondesert.com",
    "ncsoft.com",
    "*.ncsoft.com",
    "plaync.com",
    "*.plaync.com",
    "guildwars2.com",
    "*.guildwars2.com",
    "arena.net",
    "*.arena.net",
    "arenanet.com",
    "*.arenanet.com",
    "throneandliberty.com",
    "*.throneandliberty.com",
    "kakaogames.com",
    "*.kakaogames.com",
    "kakaogamescorp.com",
    "*.kakaogamescorp.com",
    "neowiz.com",
    "*.neowiz.com",
    "neowiz.co.kr",
    "*.neowiz.co.kr",
    "liesofp.com",
    "*.liesofp.com",
    "smilegate.com",
    "*.smilegate.com",
    "onstove.com",
    "*.onstove.com",
    "lostark.game",
    "*.lostark.game",
    "amazongames.com",
    "*.amazongames.com",
    "newworld.com",
    "*.newworld.com",
    "playlostark.com",
    "*.playlostark.com",
    "mihoyo.com",
    "*.mihoyo.com",
    "hoyoverse.com",
    "*.hoyoverse.com",
    "hoyolab.com",
    "*.hoyolab.com",
    "genshinimpact.com",
    "*.genshinimpact.com",
    "honkaiimpact3.com",
    "*.honkaiimpact3.com",
    "honkaistarrail.com",
    "*.honkaistarrail.com",
    "zenlesszonezero.com",
    "*.zenlesszonezero.com",
    "kurogames.com",
    "*.kurogames.com",
    "wutheringwaves.com",
    "*.wutheringwaves.com",
    "perfectworld.com",
    "*.perfectworld.com",
    "perfectworldgames.com",
    "*.perfectworldgames.com",
    "arcgames.com",
    "*.arcgames.com",
    "my.games",
    "*.my.games",
    "wargaming.net",
    "*.wargaming.net",
    "worldoftanks.com",
    "*.worldoftanks.com",
    "worldofwarships.com",
    "*.worldofwarships.com",
    "gaijin.net",
    "*.gaijin.net",
    "gaijinent.com",
    "*.gaijinent.com",
    "warthunder.com",
    "*.warthunder.com",
    "crossout.net",
    "*.crossout.net",
    "enlisted.net",
    "*.enlisted.net",
    "roblox.com",
    "*.roblox.com",
    "rbxcdn.com",
    "*.rbxcdn.com",
    "roblox.net",
    "*.roblox.net",
    "jagex.com",
    "*.jagex.com",
    "runescape.com",
    "*.runescape.com",
    "funcom.com",
    "*.funcom.com",
    "conanexiles.com",
    "*.conanexiles.com",
    "duneawakening.com",
    "*.duneawakening.com",
    "starbreeze.com",
    "*.starbreeze.com",
    "paydaythegame.com",
    "*.paydaythegame.com",
    "embark-studios.com",
    "*.embark-studios.com",
    "reachthefinals.com",
    "*.reachthefinals.com",
    "arcraiders.com",
    "*.arcraiders.com",
    "facepunch.com",
    "*.facepunch.com",
    "bohemia.net",
    "*.bohemia.net",
    "bistudio.com",
    "*.bistudio.com",
    "dayz.com",
    "*.dayz.com",
    "arma3.com",
    "*.arma3.com",
    "armaplatform.com",
    "*.armaplatform.com",
    "battlestategames.com",
    "*.battlestategames.com",
    "escapefromtarkov.com",
    "*.escapefromtarkov.com",
    "bandainamco.co.jp",
    "*.bandainamco.co.jp",
    "bandainamcoent.co.jp",
    "*.bandainamcoent.co.jp",
    "bandainamcoent.eu",
    "*.bandainamcoent.eu",
    "bandainamcoent.asia",
    "*.bandainamcoent.asia",
    "bandainamcogames.co.jp",
    "*.bandainamcogames.co.jp",
    "bn-ent.net",
    "*.bn-ent.net",
    "bn765.com",
    "*.bn765.com",
    "bandainamcoid.com",
    "*.bandainamcoid.com",
    "capcom-games.com",
    "*.capcom-games.com",
    "capcomusa.com",
    "*.capcomusa.com",
    "capcom-europe.com",
    "*.capcom-europe.com",
    "capcomid.com",
    "*.capcomid.com",
    "monsterhunter.com",
    "*.monsterhunter.com",
    "residentevil.com",
    "*.residentevil.com",
    "streetfighter.com",
    "*.streetfighter.com",
    "konami.co.jp",
    "*.konami.co.jp",
    "efootball.com",
    "*.efootball.com",
    "square-enix.net",
    "*.square-enix.net",
    "square-enix-europe.com",
    "*.square-enix-europe.com",
    "finalfantasy.com",
    "*.finalfantasy.com",
    "finalfantasyxiv.com",
    "*.finalfantasyxiv.com",
    "ffxiv.com",
    "*.ffxiv.com",
    "dragonquest.com",
    "*.dragonquest.com",
    "kingdomhearts.com",
    "*.kingdomhearts.com",
    "sega.net",
    "*.sega.net",
    "sega.jp",
    "*.sega.jp",
    "sega-europe.com",
    "*.sega-europe.com",
    "sonicthehedgehog.com",
    "*.sonicthehedgehog.com",
    "atlus.com",
    "*.atlus.com",
    "persona.com",
    "*.persona.com",
    "ryugagotoku.com",
    "*.ryugagotoku.com",
    "cygames.co.jp",
    "*.cygames.co.jp",
    "cygames.com",
    "*.cygames.com",
    "cygameseurope.com",
    "*.cygameseurope.com",
    "granbluefantasy.jp",
    "*.granbluefantasy.jp",
    "granbluefantasy.com",
    "*.granbluefantasy.com",
    "shadowverse.com",
    "*.shadowverse.com",
    "umamusume.com",
    "*.umamusume.com",
    "gunghoonline.com",
    "*.gunghoonline.com",
    "gungho.co.jp",
    "*.gungho.co.jp",
    "gungho.com",
    "*.gungho.com",
    "marvelousgames.com",
    "*.marvelousgames.com",
    "marvelous-usa.com",
    "*.marvelous-usa.com",
    "xseedgames.com",
    "*.xseedgames.com",
    "falcom.co.jp",
    "*.falcom.co.jp",
    "aksysgames.com",
    "*.aksysgames.com",
    "idea-factory.co.jp",
    "*.idea-factory.co.jp",
    "ideafintl.com",
    "*.ideafintl.com",
    "compileheart.com",
    "*.compileheart.com",
    "nippon1.jp",
    "*.nippon1.jp",
    "snk-corp.co.jp",
    "*.snk-corp.co.jp",
    "snk-corp.com",
    "*.snk-corp.com",
    "kemco.jp",
    "*.kemco.jp",
    "kemco-games.com",
    "*.kemco-games.com",
    "hamster.co.jp",
    "*.hamster.co.jp",
    "sunsoft.jp",
    "*.sunsoft.jp",
    "taito.co.jp",
    "*.taito.co.jp",
    "success-corp.co.jp",
    "*.success-corp.co.jp",
    "mages.co.jp",
    "*.mages.co.jp",
    "d3p.co.jp",
    "*.d3p.co.jp",
    "d3publisher.com",
    "*.d3publisher.com",
    "acquire.co.jp",
    "*.acquire.co.jp",
    "experience.co.jp",
    "*.experience.co.jp",
    "inti.co.jp",
    "*.inti.co.jp",
    "level5.com",
    "*.level5.com",
    "level5abby.com",
    "*.level5abby.com",
    "koei.co.jp",
    "*.koei.co.jp",
    "teamninja-studio.com",
    "*.teamninja-studio.com",
    "gust.jp",
    "*.gust.jp",
    "natsume.com",
    "*.natsume.com",
    "natsumeatari.co.jp",
    "*.natsumeatari.co.jp",
    "gamefreak.co.jp",
    "*.gamefreak.co.jp",
    "creatures.co.jp",
    "*.creatures.co.jp",
    "pokemoncenter.com",
    "*.pokemoncenter.com",
    "pokemongolive.com",
    "*.pokemongolive.com",
    "nianticlabs.com",
    "*.nianticlabs.com",
    "dena.com",
    "*.dena.com",
    "dena.jp",
    "*.dena.jp",
    "gree.net",
    "*.gree.net",
    "gree.co.jp",
    "*.gree.co.jp",
    "colopl.co.jp",
    "*.colopl.co.jp",
    "aniplex.co.jp",
    "*.aniplex.co.jp",
    "aniplexusa.com",
    "*.aniplexusa.com",
    "bushiroad.com",
    "*.bushiroad.com",
    "bushiroadgames.com",
    "*.bushiroadgames.com",
    "gamesourceentertainment.com",
    "*.gamesourceentertainment.com",
    "eastasiasoft.com",
    "*.eastasiasoft.com",
    "joycity.com",
    "*.joycity.com",
    "com2us.com",
    "*.com2us.com",
    "gamevil.com",
    "*.gamevil.com",
    "webzen.com",
    "*.webzen.com",
    "gravity.co.kr",
    "*.gravity.co.kr",
    "gravityus.com",
    "*.gravityus.com",
    "playragnarok.com",
    "*.playragnarok.com",
    "wemade.com",
    "*.wemade.com",
    "line.games",
    "*.line.games",
    "hangame.com",
    "*.hangame.com",
    "hangame.co.jp",
    "*.hangame.co.jp",
    "nexon.co.kr",
    "*.nexon.co.kr",
    "netmarble.com",
    "*.netmarble.com",
    "netmarble.net",
    "*.netmarble.net",
    "netmarble.co.kr",
    "*.netmarble.co.kr",
    "focus-entmt.com",
    "*.focus-entmt.com",
    "focus-home.com",
    "*.focus-home.com",
    "focusentertainment.com",
    "*.focusentertainment.com",
    "pullupent.com",
    "*.pullupent.com",
    "saber.games",
    "*.saber.games",
    "saber3d.com",
    "*.saber3d.com",
    "saberinteractive.com",
    "*.saberinteractive.com",
    "embracer.com",
    "*.embracer.com",
    "asmodee.com",
    "*.asmodee.com",
    "kochmedia.com",
    "*.kochmedia.com",
    "primematter.gg",
    "*.primematter.gg",
    "coffeestain.com",
    "*.coffeestain.com",
    "coffeestainstudios.com",
    "*.coffeestainstudios.com",
    "ghostship.dk",
    "*.ghostship.dk",
    "deeprockgalactic.com",
    "*.deeprockgalactic.com",
    "easybrain.com",
    "*.easybrain.com",
    "amplifiergameinvest.com",
    "*.amplifiergameinvest.com",
    "flyingwildhog.com",
    "*.flyingwildhog.com",
    "warhorse-studios.com",
    "*.warhorse-studios.com",
    "kingdomcomerpg.com",
    "*.kingdomcomerpg.com",
    "milestone.it",
    "*.milestone.it",
    "ridevideogame.com",
    "*.ridevideogame.com",
    "motogpvideogame.com",
    "*.motogpvideogame.com",
    "remedyentertainment.com",
    "*.remedyentertainment.com",
    "alanwake.com",
    "*.alanwake.com",
    "controlgame.com",
    "*.controlgame.com",
    "techland.net",
    "*.techland.net",
    "techland.pl",
    "*.techland.pl",
    "dyinglightgame.com",
    "*.dyinglightgame.com",
    "paradoxinteractive.com",
    "*.paradoxinteractive.com",
    "paradoxplaza.com",
    "*.paradoxplaza.com",
    "paradoxwikis.com",
    "*.paradoxwikis.com",
    "colossalorder.fi",
    "*.colossalorder.fi",
    "triumphstudios.com",
    "*.triumphstudios.com",
    "harebrained-schemes.com",
    "*.harebrained-schemes.com",
    "11bitstudios.com",
    "*.11bitstudios.com",
    "frostpunkgame.com",
    "*.frostpunkgame.com",
    "larian.com",
    "*.larian.com",
    "baldursgate3.game",
    "*.baldursgate3.game",
    "owlcat.games",
    "*.owlcat.games",
    "inxile-entertainment.com",
    "*.inxile-entertainment.com",
    "obsidian.net",
    "*.obsidian.net",
    "doublefine.com",
    "*.doublefine.com",
    "undeadlabs.com",
    "*.undeadlabs.com",
    "playground-games.com",
    "*.playground-games.com",
    "turn10studios.com",
    "*.turn10studios.com",
    "forza.net",
    "*.forza.net",
    "halowaypoint.com",
    "*.halowaypoint.com",
    "thecoalitionstudio.com",
    "*.thecoalitionstudio.com",
    "rare.co.uk",
    "*.rare.co.uk",
    "seaofthieves.com",
    "*.seaofthieves.com",
    "machinegames.com",
    "*.machinegames.com",
    "idsoftware.com",
    "*.idsoftware.com",
    "arkane-studios.com",
    "*.arkane-studios.com",
    "tangogameworks.com",
    "*.tangogameworks.com",
    "zenimaxonline.com",
    "*.zenimaxonline.com",
    "elderscrollsonline.com",
    "*.elderscrollsonline.com",
    "elderscrolls.com",
    "*.elderscrolls.com",
    "fallout.com",
    "*.fallout.com",
    "doom.com",
    "*.doom.com",
    "quake.com",
    "*.quake.com",
    "wolfenstein.com",
    "*.wolfenstein.com",
    "starfieldgame.com",
    "*.starfieldgame.com",
    "infinityward.com",
    "*.infinityward.com",
    "treyarch.com",
    "*.treyarch.com",
    "sledgehammergames.com",
    "*.sledgehammergames.com",
    "ravensoftware.com",
    "*.ravensoftware.com",
    "highmoonstudios.com",
    "*.highmoonstudios.com",
    "beenox.com",
    "*.beenox.com",
    "toysforbob.com",
    "*.toysforbob.com",
    "king.com",
    "*.king.com",
    "candycrush.com",
    "*.candycrush.com",
    "blizzard.cn",
    "*.blizzard.cn",
    "playoverwatch.com",
    "*.playoverwatch.com",
    "diablo.com",
    "*.diablo.com",
    "worldofwarcraft.com",
    "*.worldofwarcraft.com",
    "hearthstone.com",
    "*.hearthstone.com",
    "heroesofthestorm.com",
    "*.heroesofthestorm.com",
    "starcraft.com",
    "*.starcraft.com",
    "activisionblizzard.com",
    "*.activisionblizzard.com",
    "rockstarnorth.com",
    "*.rockstarnorth.com",
    "grandtheftauto.com",
    "*.grandtheftauto.com",
    "reddeadredemption.com",
    "*.reddeadredemption.com",
    "gearboxpublishing.com",
    "*.gearboxpublishing.com",
    "borderlands.com",
    "*.borderlands.com",
    "firaxis.com",
    "*.firaxis.com",
    "civilization.com",
    "*.civilization.com",
    "xcom.com",
    "*.xcom.com",
    "hangar13games.com",
    "*.hangar13games.com",
    "visualconcepts.com",
    "*.visualconcepts.com",
    "privatedivision.com",
    "*.privatedivision.com",
    "ghoststorygames.com",
    "*.ghoststorygames.com",
    "interceptgames.com",
    "*.interceptgames.com",
    "roll7.co.uk",
    "*.roll7.co.uk",
    "zynga.com",
    "*.zynga.com",
    "zyngagames.com",
    "*.zyngagames.com",
    "naturalmotion.com",
    "*.naturalmotion.com",
    "socialpoint.es",
    "*.socialpoint.es",
    "smallgiantgames.com",
    "*.smallgiantgames.com",
    "supercell.com",
    "*.supercell.com",
    "supercell.net",
    "*.supercell.net",
    "clashofclans.com",
    "*.clashofclans.com",
    "clashroyale.com",
    "*.clashroyale.com",
    "brawlstars.com",
    "*.brawlstars.com",
    "hayday.com",
    "*.hayday.com",
    "spaceapegames.com",
    "*.spaceapegames.com",
    "electronicarts.com",
    "*.electronicarts.com",
    "respawn.com",
    "*.respawn.com",
    "apexlegends.com",
    "*.apexlegends.com",
    "titanfall.com",
    "*.titanfall.com",
    "bioware.com",
    "*.bioware.com",
    "dice.se",
    "*.dice.se",
    "battlefield.com",
    "*.battlefield.com",
    "criteriongames.com",
    "*.criteriongames.com",
    "motive-studios.com",
    "*.motive-studios.com",
    "maxis.com",
    "*.maxis.com",
    "thesims.com",
    "*.thesims.com",
    "popcap.com",
    "*.popcap.com",
    "glumobile.com",
    "*.glumobile.com",
    "playdemic.com",
    "*.playdemic.com",
    "massive.se",
    "*.massive.se",
    "redlynx.com",
    "*.redlynx.com",
    "bluemammoth.com",
    "*.bluemammoth.com",
    "brawlhalla.com",
    "*.brawlhalla.com",
    "trackmania.com",
    "*.trackmania.com",
    "anno-union.com",
    "*.anno-union.com",
    "assassinscreed.com",
    "*.assassinscreed.com",
    "justdance.com",
    "*.justdance.com",
    "farcry.com",
    "*.farcry.com",
    "thedivisiongame.com",
    "*.thedivisiongame.com",
    "wbgames.net",
    "*.wbgames.net",
    "wbagora.com",
    "*.wbagora.com",
    "netherrealm.com",
    "*.netherrealm.com",
    "mortalkombat.com",
    "*.mortalkombat.com",
    "avalanchesoftware.com",
    "*.avalanchesoftware.com",
    "portkeygames.com",
    "*.portkeygames.com",
    "hogwartslegacy.com",
    "*.hogwartslegacy.com",
    "rocksteadyltd.com",
    "*.rocksteadyltd.com",
    "multiversus.com",
    "*.multiversus.com",
    "playerfirstgames.com",
    "*.playerfirstgames.com",
    "atari.com",
    "*.atari.com",
    "nightdivestudios.com",
    "*.nightdivestudios.com",
    "digitaleclipse.com",
    "*.digitaleclipse.com",
    "limitedrungames.com",
    "*.limitedrungames.com",
    "pqube.co.uk",
    "*.pqube.co.uk",
    "pqube.com",
    "*.pqube.com",
    "playism.com",
    "*.playism.com",
    "playism.jp",
    "*.playism.jp",
    "ratalaikagames.com",
    "*.ratalaikagames.com",
    "sometimesyou.com",
    "*.sometimesyou.com",
    "jandusoft.com",
    "*.jandusoft.com",
    "playway.com",
    "*.playway.com",
    "ultimate-games.com",
    "*.ultimate-games.com",
    "klabater.com",
    "*.klabater.com",
    "outrightgames.com",
    "*.outrightgames.com",
    "tophatstudios.com",
    "*.tophatstudios.com",
    "superpowerupgames.com",
    "*.superpowerupgames.com",
    "qubyteinteractive.com",
    "*.qubyteinteractive.com",
    "redartgames.com",
    "*.redartgames.com",
    "strictlylimitedgames.com",
    "*.strictlylimitedgames.com",
    "pixelheart.eu",
    "*.pixelheart.eu",
    "numskullgames.com",
    "*.numskullgames.com",
    "mergegames.com",
    "*.mergegames.com",
    "maximum-ent.com",
    "*.maximum-ent.com",
    "modusgames.com",
    "*.modusgames.com",
    "justforgames.com",
    "*.justforgames.com",
    "kepler-interactive.com",
    "*.kepler-interactive.com",
    "playstack.com",
    "*.playstack.com",
    "kwalee.com",
    "*.kwalee.com",
    "nomorerobots.io",
    "*.nomorerobots.io",
    "team17digital.com",
    "*.team17digital.com",
    "digitalbros.com",
    "*.digitalbros.com",
    "nacongaming.com",
    "*.nacongaming.com",
    "bigben.fr",
    "*.bigben.fr",
    "cyanide-studio.com",
    "*.cyanide-studio.com",
    "spiders-games.com",
    "*.spiders-games.com",
    "kt-racing.com",
    "*.kt-racing.com",
    "bigant.com",
    "*.bigant.com",
    "bigantstudios.com",
    "*.bigantstudios.com",
    "artefacts-studio.fr",
    "*.artefacts-studio.fr",
    "dont-nod.com",
    "*.dont-nod.com",
    "dontnod.com",
    "*.dontnod.com",
    "asobostudio.com",
    "*.asobostudio.com",
    "sloclap.com",
    "*.sloclap.com",
    "giants-software.com",
    "*.giants-software.com",
    "farming-simulator.com",
    "*.farming-simulator.com",
    "astragon.com",
    "*.astragon.com",
    "astragon.de",
    "*.astragon.de",
    "kalypsomedia.com",
    "*.kalypsomedia.com",
    "kalypsomedia.de",
    "*.kalypsomedia.de",
    "slitherine.com",
    "*.slitherine.com",
    "matrixgames.com",
    "*.matrixgames.com",
    "aerosoft.com",
    "*.aerosoft.com",
    "scssoft.com",
    "*.scssoft.com",
    "truckersmp.com",
    "*.truckersmp.com",
    "beamng.com",
    "*.beamng.com",
    "keenswh.com",
    "*.keenswh.com",
    "spaceengineersgame.com",
    "*.spaceengineersgame.com",
    "re-logic.com",
    "*.re-logic.com",
    "terraria.org",
    "*.terraria.org",
    "terraria.com",
    "*.terraria.com",
    "stardewvalley.net",
    "*.stardewvalley.net",
    "chucklefish.org",
    "*.chucklefish.org",
    "chucklefishgames.com",
    "*.chucklefishgames.com",
    "supergiantgames.com",
    "*.supergiantgames.com",
    "motion-twin.com",
    "*.motion-twin.com",
    "evilempirestudio.com",
    "*.evilempirestudio.com",
    "sabotagestudio.com",
    "*.sabotagestudio.com",
    "teamcherry.com.au",
    "*.teamcherry.com.au",
    "hollowknight.com",
    "*.hollowknight.com",
    "moonstudios.com",
    "*.moonstudios.com",
    "gsc-game.com",
    "*.gsc-game.com",
    "stalker2.com",
    "*.stalker2.com",
    "4a-games.com",
    "*.4a-games.com",
    "metrothegame.com",
    "*.metrothegame.com",
    "peoplecanfly.com",
    "*.peoplecanfly.com",
    "cigames.com",
    "*.cigames.com",
    "hexworks.com",
    "*.hexworks.com",
    "lordsofthefallen.com",
    "*.lordsofthefallen.com",
    "blooberteam.com",
    "*.blooberteam.com",
    "blooberteam.pl",
    "*.blooberteam.pl",
    "frozendistrict.com",
    "*.frozendistrict.com",
    "houseflippergame.com",
    "*.houseflippergame.com",
    "tensquaregames.com",
    "*.tensquaregames.com",
    "artifexmundi.com",
    "*.artifexmundi.com",
    "herocraft.com",
    "*.herocraft.com",
    "alawar.com",
    "*.alawar.com",
    "alawar.ru",
    "*.alawar.ru",
    "nicalis.com",
    "*.nicalis.com",
    "nighthawkinteractive.com",
    "*.nighthawkinteractive.com",
    "pm-studios.com",
    "*.pm-studios.com",
    "pmstudios.com",
    "*.pmstudios.com",
    "headupgames.com",
    "*.headupgames.com",
    "headupgames.de",
    "*.headupgames.de",
    "untoldtales.games",
    "*.untoldtales.games",
    "neondoctrine.com",
    "*.neondoctrine.com",
    "whitethorngames.com",
    "*.whitethorngames.com",
    "fellowtraveller.games",
    "*.fellowtraveller.games",
    "thunderfulgames.com",
    "*.thunderfulgames.com",
    "thunderfulgroup.com",
    "*.thunderfulgroup.com",
    "imageform.se",
    "*.imageform.se",
    "risingstargames.com",
    "*.risingstargames.com",
    "armorgames.com",
    "*.armorgames.com",
    "newgrounds.com",
    "*.newgrounds.com",
    "kongregate.com",
    "*.kongregate.com",
    "miniclip.com",
    "*.miniclip.com",
    "gameloft.com",
    "*.gameloft.com",
    "gameloft.org",
    "*.gameloft.org",
    "scopely.com",
    "*.scopely.com",
    "scopely.io",
    "*.scopely.io",
    "monopolygo.com",
    "*.monopolygo.com",
    "niantic.com",
    "*.niantic.com",
    "playrix.com",
    "*.playrix.com",
    "playrix.net",
    "*.playrix.net",
    "dreamgames.com",
    "*.dreamgames.com",
    "royalmatch.com",
    "*.royalmatch.com",
    "lilithgames.com",
    "*.lilithgames.com",
    "igg.com",
    "*.igg.com",
    "igg.net",
    "*.igg.net",
    "funplus.com",
    "*.funplus.com",
    "funplusgames.com",
    "*.funplusgames.com",
    "yostar.com",
    "*.yostar.com",
    "yostar.co.jp",
    "*.yostar.co.jp",
    "yo-star.com",
    "*.yo-star.com",
    "hypergryph.com",
    "*.hypergryph.com",
    "arknights.global",
    "*.arknights.global",
    "arknights.com",
    "*.arknights.com",
    "gryphline.com",
    "*.gryphline.com",
    "sunborn.com",
    "*.sunborn.com",
    "girlsfrontline.com",
    "*.girlsfrontline.com",
    "papegames.com",
    "*.papegames.com",
    "infoldgames.com",
    "*.infoldgames.com",
    "infinitynikki.com",
    "*.infinitynikki.com",
    "loveanddeepspace.com",
    "*.loveanddeepspace.com",
    "bilibiligame.com",
    "*.bilibiligame.com",
    "biligame.com",
    "*.biligame.com",
    "taptap.com",
    "*.taptap.com",
    "taptap.cn",
    "*.taptap.cn",
    "heartmachine.com",
    "*.heartmachine.com",
    "thatgamecompany.com",
    "*.thatgamecompany.com",
    "skychildrenofthelight.com",
    "*.skychildrenofthelight.com",
    "mobiusdigitalgames.com",
    "*.mobiusdigitalgames.com",
    "outerwilds.com",
    "*.outerwilds.com",
    "unknownworlds.com",
    "*.unknownworlds.com",
    "subnautica.com",
    "*.subnautica.com",
    "irongatestudio.se",
    "*.irongatestudio.se",
    "valheimgame.com",
    "*.valheimgame.com",
    "studiowildcard.com",
    "*.studiowildcard.com",
    "survivetheark.com",
    "*.survivetheark.com",
    "playark.com",
    "*.playark.com",
    "snailgamesusa.com",
    "*.snailgamesusa.com",
    "snailgames.com",
    "*.snailgames.com",
    "pocketpair.jp",
    "*.pocketpair.jp",
    "palworldgame.com",
    "*.palworldgame.com",
    "satisfactorygame.com",
    "*.satisfactorygame.com",
    "tripwireinteractive.com",
    "*.tripwireinteractive.com",
    "killingfloor2.com",
    "*.killingfloor2.com",
    "tornbanner.com",
    "*.tornbanner.com",
    "chivalry2.com",
    "*.chivalry2.com",
    "irongalaxystudios.com",
    "*.irongalaxystudios.com",
    "guninteractive.com",
    "*.guninteractive.com",
    "txchainsawgame.com",
    "*.txchainsawgame.com",
    "sumo-digital.com",
    "*.sumo-digital.com",
    "sumogroupplc.com",
    "*.sumogroupplc.com",
    "secretmode.games",
    "*.secretmode.games",
    "rebellion.com",
    "*.rebellion.com",
    "rebellion.co.uk",
    "*.rebellion.co.uk",
    "sniperelite.com",
    "*.sniperelite.com",
    "d3t.co.uk",
    "*.d3t.co.uk",
    "double11.com",
    "*.double11.com",
    "doubleeleven.com",
    "*.doubleeleven.com",
    "splashdamage.com",
    "*.splashdamage.com",
    "supermassivegames.com",
    "*.supermassivegames.com",
    "darkpictures.com",
    "*.darkpictures.com",
    "steelwoolstudios.com",
    "*.steelwoolstudios.com",
    "steelwoolgames.com",
    "*.steelwoolgames.com",
    "scottgames.com",
    "*.scottgames.com",
    "mobentertainment.com",
    "*.mobentertainment.com",
    "poppyplaytime.com",
    "*.poppyplaytime.com",
    "kineticgames.co.uk",
    "*.kineticgames.co.uk",
    "phasmophobia.com",
    "*.phasmophobia.com",
    "innersloth.com",
    "*.innersloth.com",
    "amongus.com",
    "*.amongus.com",
    "mediatonicgames.com",
    "*.mediatonicgames.com",
    "hellogames.org",
    "*.hellogames.org",
    "nomanssky.com",
    "*.nomanssky.com",
    "frontier.co.uk",
    "*.frontier.co.uk",
    "frontierdevelopments.com",
    "*.frontierdevelopments.com",
    "elitedangerous.com",
    "*.elitedangerous.com",
    "jurassicworldevolution.com",
    "*.jurassicworldevolution.com",
    "planetcoaster.com",
    "*.planetcoaster.com",
    "planetzoogame.com",
    "*.planetzoogame.com",
    "battleye.com",
    "*.battleye.com",
    "punkbuster.com",
    "*.punkbuster.com",
    "evenbalance.com",
    "*.evenbalance.com",
    "gamespy.com",
    "*.gamespy.com",
    "gamesparks.com",
    "*.gamesparks.com",
    "gamesparks.net",
    "*.gamesparks.net",
    "photonengine.com",
    "*.photonengine.com",
    "exitgames.com",
    "*.exitgames.com",
    "photoncloud.com",
    "*.photoncloud.com",
    "vivox.com",
    "*.vivox.com",
    "vivox.net",
    "*.vivox.net",
    "accelbyte.io",
    "*.accelbyte.io",
    "pragma.gg",
    "*.pragma.gg",
    "heroiclabs.com",
    "*.heroiclabs.com",
    "mod.io",
    "*.mod.io",
    "modio.com",
    "*.modio.com",
    "gameanalytics.com",
    "*.gameanalytics.com",
    "gameanalytics.io",
    "*.gameanalytics.io",
    "deltadna.net",
    "*.deltadna.net",
    "deltadna.com",
    "*.deltadna.com",
    "gamesight.io",
    "*.gamesight.io",
    "gameye.com",
    "*.gameye.com",
    "edgegap.com",
    "*.edgegap.com",
    "geforcenow.com",
    "*.geforcenow.com",
    "boosteroid.com",
    "*.boosteroid.com",
    "blacknut.com",
    "*.blacknut.com",
    "luna.amazon.com",
    "*.luna.amazon.com",
    "oculus.com",
    "*.oculus.com",
    "oculuscdn.com",
    "*.oculuscdn.com",
    "metaquest.com",
    "*.metaquest.com",
    "vive.com",
    "*.vive.com",
    "viveport.com",
    "*.viveport.com",
    "pico-interactive.com",
    "*.pico-interactive.com",
    "picoxr.com",
    "*.picoxr.com",
    "pvp.net",
    "*.pvp.net",
    "riotgamespatcher-a.akamaihd.net",
    "*.riotgamespatcher-a.akamaihd.net",
    "game.qq.com",
    "*.game.qq.com",
    "tdm.qq.com",
    "*.tdm.qq.com",
    "garena.com",
    "*.garena.com",
    "garena.sg",
    "*.garena.sg",
    "garena.vn",
    "*.garena.vn",
    "garena.tw",
    "*.garena.tw",
    "freefire.com",
    "*.freefire.com",
    "freefiremobile.com",
    "*.freefiremobile.com",
    "gameforge.com",
    "*.gameforge.com",
    "gameforge.de",
    "*.gameforge.de",
    "gameforge.net",
    "*.gameforge.net",
    "aiononline.com",
    "*.aiononline.com",
    "lineage2.com",
    "*.lineage2.com",
    "ncamerica.com",
    "*.ncamerica.com",
    "hoodedhorse.com",
    "*.hoodedhorse.com",
    "fulqrumpublishing.com",
    "*.fulqrumpublishing.com",
    "1cpublishing.eu",
    "*.1cpublishing.eu",
    "superraregames.com",
    "*.superraregames.com",
    "ripstone.com",
    "*.ripstone.com",
    "resolutiongames.com",
    "*.resolutiongames.com",
    "survios.com",
    "*.survios.com",
    "squanchgames.com",
    "*.squanchgames.com",
    "joeydrewstudios.com",
    "*.joeydrewstudios.com",
    "sunblink.com",
    "*.sunblink.com",
    "weakfishstudio.com",
    "*.weakfishstudio.com",
    "meridiem-games.com",
    "*.meridiem-games.com",
    "avalanche-studios.com",
    "*.avalanche-studios.com",
    "avalanchestudios.com",
    "*.avalanchestudios.com",
    "destructivecreations.com",
    "*.destructivecreations.com",
    "ehomegames.com",
    "*.ehomegames.com",
    "gamesincubator.com",
    "*.gamesincubator.com",
    "blitworks.com",
    "*.blitworks.com",
    "cfk.kr",
    "*.cfk.kr",
    "skystone.games",
    "*.skystone.games",
    "monster-games.com",
    "*.monster-games.com",
    "pix-arts.com",
    "*.pix-arts.com",
    "oceanmedia.hr",
    "*.oceanmedia.hr",
    "entergram.co.jp",
    "*.entergram.co.jp",
    "lightwoodgames.com",
    "*.lightwoodgames.com",
    "lillymogames.com",
    "*.lillymogames.com",
    "anvilstudios.com",
    "*.anvilstudios.com",
    "synnergycirclegames.com",
    "*.synnergycirclegames.com",
    "digitalcybercherries.com",
    "*.digitalcybercherries.com",
    "hyperchargegame.com",
    "*.hyperchargegame.com",
    "grip-digital.com",
    "*.grip-digital.com",
    "wiredproductions.com",
    "*.wiredproductions.com",
    "ustwogames.co.uk",
    "*.ustwogames.co.uk",
    "redhookstudios.com",
    "*.redhookstudios.com",
    "darkestdungeon.com",
    "*.darkestdungeon.com",
    "nightdive.com",
    "*.nightdive.com",
    "rainmakerproductions.com",
    "*.rainmakerproductions.com",
    "iam8bit.com",
    "*.iam8bit.com",
    "shepherd.games",
    "*.shepherd.games",
    "goodshepherd.games",
    "*.goodshepherd.games",
    "rawthrills.com",
    "*.rawthrills.com",
    "thalamusdigital.com",
    "*.thalamusdigital.com",
    "curve-digital.com",
    "*.curve-digital.com",
    "firesidegames.com",
    "*.firesidegames.com",
    "2awesome.studio",
    "*.2awesome.studio",
    "superrare.games",
    "*.superrare.games",
    "hitcents.com",
    "*.hitcents.com",
    "team-reptile.com",
    "*.team-reptile.com",
    "teamreptile.com",
    "*.teamreptile.com",
    "noxcrew.com",
    "*.noxcrew.com",
    "tinybuildgames.com",
    "*.tinybuildgames.com",
    "snowcastle.games",
    "*.snowcastle.games",
    "snowcastlegames.com",
    "*.snowcastlegames.com",
    "inin.games",
    "*.inin.games",
    "unitedgames-entertainment.com",
    "*.unitedgames-entertainment.com",
    "justdan.com",
    "*.justdan.com",
    "justdan.com.tw",
    "*.justdan.com.tw",
    "redgames.co",
    "*.redgames.co",
    "redgamesco.com",
    "*.redgamesco.com",
    "zenstudios.com",
    "*.zenstudios.com",
    "frozenbyte.com",
    "*.frozenbyte.com",
    "frogwares.com",
    "*.frogwares.com",
    "madheadgames.com",
    "*.madheadgames.com",
    "stormindgames.com",
    "*.stormindgames.com",
    "blackforestgames.com",
    "*.blackforestgames.com",
    "mimimi.games",
    "*.mimimi.games",
    "ic.com",
    "*.ic.com",
    "daedalic.com",
    "*.daedalic.com",
    "deck13.com",
    "*.deck13.com",
    "deck13.de",
    "*.deck13.de",
    "deck13spotlight.com",
    "*.deck13spotlight.com",
    "runningwithscissors.com",
    "*.runningwithscissors.com",
    "postal.game",
    "*.postal.game",
    "pathofexile.com",
    "*.pathofexile.com",
    "grindinggear.com",
    "*.grindinggear.com",
    "grindinggear.games",
    "*.grindinggear.games",
    "pathofexile2.com",
    "*.pathofexile2.com",
    "eadp.net",
    "*.eadp.net",
    "warface.com",
    "*.warface.com",
    "paladins.com",
    "*.paladins.com",
    "roguecompany.com",
    "*.roguecompany.com",
    "smite2.com",
    "*.smite2.com",
    "hirez.com",
    "*.hirez.com",
    "rainbow6.com",
    "*.rainbow6.com",
    "turtlerockstudios.com",
    "*.turtlerockstudios.com",
    "back4blood.com",
    "*.back4blood.com",
    "left4dead.com",
    "*.left4dead.com",
    "counter-strike.net",
    "*.counter-strike.net",
    "dota2.com",
    "*.dota2.com",
    "teamfortress.com",
    "*.teamfortress.com",
    "half-life.com",
    "*.half-life.com",
    "steamchina.com",
    "*.steamchina.com",
    "steamchina.com.cn",
    "*.steamchina.com.cn",
    "riftgame.com",
    "*.riftgame.com",
    "trionworlds.com",
    "*.trionworlds.com",
    "gamigo.com",
    "*.gamigo.com",
    "gamigo.net",
    "*.gamigo.net",
    "glyph.net",
    "*.glyph.net",
    "archeage.com",
    "*.archeage.com",
    "unitygamingservices.com",
    "*.unitygamingservices.com",
    "cloud.unity3d.com",
    "*.cloud.unity3d.com",
    "services.unity.com",
    "*.services.unity.com",
    "relay.unity3d.com",
    "*.relay.unity3d.com",
    "matchmaker.unity3d.com",
    "*.matchmaker.unity3d.com",
    "unityads.unity3d.com",
    "*.unityads.unity3d.com",
    "ads.unity.com",
    "*.ads.unity.com",
    "unityads.com",
    "*.unityads.com",
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
    if(errno == EEXIST && stat(path, &st) == 0 && S_ISDIR(st.st_mode)) return 0;
    return -1;
  }

  return 1;
}

/* Kernel-owned record lock: no PID guessing, stale PID files or forced kill.
 * The file persists intentionally; closing the fd/process releases the lock. */
static int
acquire_instance_lock(const char *path) {
  struct stat st;
  struct flock lock;
  int fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
  if(fd < 0) return -1;
  if(fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    int saved = errno ? errno : EINVAL;
    close(fd);
    errno = saved;
    return -1;
  }
  memset(&lock, 0, sizeof(lock));
  lock.l_type = F_WRLCK;
  lock.l_whence = SEEK_SET;
  if(fcntl(fd, F_SETLK, &lock) != 0) {
    int saved = errno;
    close(fd);
    errno = saved;
    return -1;
  }
  return fd;
}

/* Choose one profile; never downgrade on invalid or inaccessible paths. */
static int
select_config_path(const char *preferred, const char *legacy,
                   const char **selected) {
  struct stat st;
  *selected = preferred;
  if(lstat(preferred, &st) == 0) return 0;
  if(errno != ENOENT) return -1;
  if(lstat(legacy, &st) == 0) {
    *selected = legacy;
    return 0;
  }
  if(errno != ENOENT) {
    *selected = legacy;
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
set_socket_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if(flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0)
    return -1;
  return 0;
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

  if(set_socket_nonblocking(fd) != 0) {
    close(fd);
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

  if(set_socket_nonblocking(fd) != 0) {
    log_errno("nonblocking(server-ipv4)");
    close(fd);
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

  if(set_socket_nonblocking(fd) != 0) {
    log_errno("nonblocking(server-ipv6)");
    close(fd);
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

      /* Recheck stop even if the signal arrived between the condition and poll. */
      int wait_ms = timeout_ms > 100 ? 100 : (int)timeout_ms;
      poll_rc = poll(&pfd, 1, wait_ms);
      if(!g_running) return -1;
      if(poll_rc == 0) continue;

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
  if(!g_running) return;
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
  int config_state = 0;
  const char *config_path = CONFIG_PATH;
  int config_errno = 0;
  int config_loaded = 0;
  int data_dir_state;
  int data_dir_errno = 0;
  int instance_fd = -1;
  struct sigaction stop_action;

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
  memset(&stop_action, 0, sizeof(stop_action));
  stop_action.sa_handler = on_signal;
  sigemptyset(&stop_action.sa_mask);
  if(sigaction(SIGINT, &stop_action, NULL) != 0 ||
     sigaction(SIGTERM, &stop_action, NULL) != 0) {
    return EXIT_FAILURE;
  }

  data_dir_state = ensure_runtime_dir_exists(DATA_DIR);
  if(data_dir_state < 0) {
    data_dir_errno = errno;
  }

  /* Admission precedes config/log mutations and all SceNet work. */
  if(!g_running) return EXIT_SUCCESS;
  instance_fd = acquire_instance_lock(INSTANCE_LOCK_PATH);
  if(instance_fd < 0) {
    log_printf("[nanodns] startup refused: instance lock unavailable (errno=%d)\n", errno);
    return EXIT_FAILURE;
  }
  if(!g_running) { close(instance_fd); return EXIT_SUCCESS; }

  int selection = select_config_path(CONFIG_PATH, LEGACY_CONFIG_PATH, &config_path);
  if(selection == 1) {
    config_state = ensure_default_config_exists(config_path);
    if(config_state < 0) config_errno = errno;
  } else if(selection < 0) {
    config_state = -1;
    config_errno = errno;
  }

  if(selection < 0 || load_config(config_path, &cfg) != 0) {
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
    log_printf("[nanodns] created default config at %s\n", config_path);
  } else if(config_state < 0) {
    log_printf("[nanodns] could not select/create %s: %s\n", config_path,
               strerror(config_errno));
  }

  if(!config_loaded) {
    log_printf("[nanodns] could not fully load %s, using compiled defaults only\n",
               config_path);
  }
  log_printf("[nanodns] config-source=%s selected-path=%s mandatory-rules=%zu\n",
             config_loaded ? "file" : "compiled", config_path,
             (size_t)PROTECTED_RULE_COUNT);

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
  if(!g_running) {
    logger_fini();
    config_release(&cfg);
    close(instance_fd);
    return EXIT_SUCCESS;
  }
  if(elevate_privileges() != 0) {
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    logger_fini();
    config_release(&cfg);
    close(instance_fd);
    return EXIT_FAILURE;
  }

  if(net_init() != 0) {
    close_upstream_sockets(upstream_fds, MAX_UPSTREAMS);
    logger_fini();
    config_release(&cfg);
    close(instance_fd);
    return 1;
  }

  for(size_t i = 0; i < SERVER_LISTENER_COUNT && g_running; ++i) {
    (void)open_server_listener(&cfg, &listeners[i]);
  }

  /* IPv6 alone does not protect an IPv4-configured console.  Most
   * importantly, never run half-active beside an old IPv4 nanoDNS. */
  if(!g_running) goto shutdown;
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
    close(instance_fd);
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

  if(g_running && !cfg.quiet_enabled) {
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

shutdown:
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
  close(instance_fd);
  return 0;
}
