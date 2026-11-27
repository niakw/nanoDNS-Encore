#ifndef NANODNS_NANOFIREWALL_FEED_H
#define NANODNS_NANOFIREWALL_FEED_H

#include <sys/socket.h>
#include <stddef.h>

#define NANOFIREWALL_FEED_PATH "/data/nanofirewall/dns-feed.sock"
#define NANOFIREWALL_INTERNAL_DNS_SOURCE_PORT 54053u

/* Best effort: returns 1 if queued, 0 if nanoFirewall is absent/unavailable.
 * Never makes DNS serving depend on the firewall. */
int nanofirewall_feed_notify(const char *hostname);

/* Firewall's own independent localhost re-resolution must not recurse back
 * into the observation feed. */
int nanofirewall_feed_is_internal_client(
    const struct sockaddr *client,
    socklen_t client_len);

void nanofirewall_feed_close(void);

#endif
