#include "nanofirewall_feed.h"

#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define FEED_WIRE_SIZE 280u
#define FEED_DOMAIN_MAX 253u

enum {
    O_MAGIC=0,
    O_VERSION=4,
    O_SIZE=6,
    O_SEQUENCE=8,
    O_DOMAIN_LENGTH=16,
    O_DOMAIN=20,
    O_CHECKSUM=276
};

static int g_feed_fd=-1;
static uint64_t g_last_sequence=0;

static void put16(uint8_t *p,uint16_t value) {
    p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);
}
static void put32(uint8_t *p,uint32_t value) {
    for(unsigned i=0;i<4;++i)
        p[i]=(uint8_t)(value>>(8u*i));
}
static void put64(uint8_t *p,uint64_t value) {
    for(unsigned i=0;i<8;++i)
        p[i]=(uint8_t)(value>>(8u*i));
}
static uint32_t crc32_bytes(const uint8_t *data,size_t length) {
    uint32_t crc=0xffffffffu;
    for(size_t i=0;i<length;++i) {
        crc^=data[i];
        for(unsigned bit=0;bit<8;++bit)
            crc=(crc>>1)^((0u-(crc&1u))&0xedb88320u);
    }
    return ~crc;
}
static int normalize(const char *input,char out[FEED_DOMAIN_MAX+1u]) {
    if(!input||!out)
        return 0;
    size_t n=strlen(input);
    while(n&&input[n-1u]=='.')
        --n;
    if(n==0||n>FEED_DOMAIN_MAX)
        return 0;

    size_t label=0;
    for(size_t i=0;i<n;++i) {
        unsigned char ch=(unsigned char)input[i];
        if(ch=='.') {
            if(label==0||label>63u)
                return 0;
            out[i]='.';label=0;
        } else if(isalnum(ch)||ch=='-'||ch=='_') {
            out[i]=(char)tolower(ch);++label;
        } else {
            return 0;
        }
    }
    if(label==0||label>63u)
        return 0;
    out[n]='\0';
    return 1;
}
static uint64_t next_sequence(void) {
    struct timespec now;
    memset(&now,0,sizeof(now));
    (void)clock_gettime(CLOCK_MONOTONIC,&now);
    uint64_t seq=(uint64_t)now.tv_sec*1000000000ull+
                 (uint64_t)now.tv_nsec;
    if(seq<=g_last_sequence)
        seq=g_last_sequence+1u;
    g_last_sequence=seq?seq:1u;
    return g_last_sequence;
}
static int ensure_socket(void) {
    if(g_feed_fd>=0)
        return 0;
    int fd=socket(AF_UNIX,SOCK_DGRAM,0);
    if(fd<0)
        return -1;
    int flags=fcntl(fd,F_GETFL,0);
    if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)!=0) {
        close(fd);return -1;
    }
    g_feed_fd=fd;
    return 0;
}

int nanofirewall_feed_notify(const char *hostname) {
    char normalized[FEED_DOMAIN_MAX+1u];
    if(!normalize(hostname,normalized))
        return 0;
    if(ensure_socket()!=0)
        return 0;

    uint8_t wire[FEED_WIRE_SIZE];
    memset(wire,0,sizeof(wire));
    wire[0]='N';wire[1]='F';wire[2]='D';wire[3]='1';
    put16(wire+O_VERSION,1u);
    put16(wire+O_SIZE,FEED_WIRE_SIZE);
    put64(wire+O_SEQUENCE,next_sequence());
    size_t n=strlen(normalized);
    put16(wire+O_DOMAIN_LENGTH,(uint16_t)n);
    memcpy(wire+O_DOMAIN,normalized,n);
    put32(wire+O_CHECKSUM,crc32_bytes(wire,O_CHECKSUM));

    struct sockaddr_un peer;
    memset(&peer,0,sizeof(peer));
    peer.sun_family=AF_UNIX;
    if(strlen(NANOFIREWALL_FEED_PATH)>=sizeof(peer.sun_path))
        return 0;
    strcpy(peer.sun_path,NANOFIREWALL_FEED_PATH);

    ssize_t sent=sendto(g_feed_fd,wire,sizeof(wire),MSG_DONTWAIT,
                        (const struct sockaddr *)&peer,sizeof(peer));
    memset(wire,0,sizeof(wire));
    if(sent==(ssize_t)FEED_WIRE_SIZE)
        return 1;

    if(errno==ENOENT||errno==ECONNREFUSED||errno==EAGAIN||
       errno==EWOULDBLOCK) {
        close(g_feed_fd);g_feed_fd=-1;
    }
    return 0;
}

int nanofirewall_feed_is_internal_client(
    const struct sockaddr *client,
    socklen_t client_len) {
    if(!client)
        return 0;

    if(client->sa_family==AF_INET &&
       client_len>=sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *v4=
            (const struct sockaddr_in *)client;
        return v4->sin_addr.s_addr==htonl(INADDR_LOOPBACK) &&
               ntohs(v4->sin_port)==
                   NANOFIREWALL_INTERNAL_DNS_SOURCE_PORT;
    }
    if(client->sa_family==AF_INET6 &&
       client_len>=sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *v6=
            (const struct sockaddr_in6 *)client;
        static const uint8_t loopback[16]=
            {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
        return memcmp(&v6->sin6_addr,loopback,16)==0 &&
               ntohs(v6->sin6_port)==
                   NANOFIREWALL_INTERNAL_DNS_SOURCE_PORT;
    }
    return 0;
}

void nanofirewall_feed_close(void) {
    if(g_feed_fd>=0)
        close(g_feed_fd);
    g_feed_fd=-1;
    g_last_sequence=0;
}
