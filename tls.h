#ifndef _tls_h_
#define _tls_h_

#include <netinet/in.h>
#include <arpa/inet.h>
#include "util.h"

#define MAX_NAME_LEN 50

typedef u_char content_t;
/*
    change_cipher_spec = 20(0x14),
    alert = 21(0x15),
    handshake = 22(0x16),
    application_data = 23(0x17)
*/

typedef u_char handshake_t;
/*
    hello_request = 0(0x00),
    client_hello = 1(0x01),
    server_hello = 2(0x02),
    certificate = 11(0x0b),
    server_key_exchange = 12(0x0c),
    certificate_request = 13(0x0d),
    server_hello_done = 14(0x0e),
    certificate_verify = 15(0x0f),
    client_key_exchange = 16(0x10),
    finished = 20(0x14)
*/

typedef u_int16_t extension_t;
/*
    Reserved = 64250(0xfafa)
    server_name = 0
    extended_master_secret = 23(0x17)
*/

typedef struct
{
    u_int8_t major;
    u_int8_t minor;
} __attribute__((packed)) protocol_version_t;
/*
    SSL = {0x03, 0x00}
    TLS v1.0 = {0x03, 0x01}
    TLS v1.1 = {0x03, 0x02}
    TLS v1.2 = {0x03, 0x03}
*/

typedef struct
{
    u_int32_t gmt_unix_time;
    u_char random_bytes[28];
} __attribute__((packed)) random_t;

typedef struct
{
    u_char id[32];
} __attribute__((packed)) session_id_t;

typedef struct
{
    u_int16_t suite;
} __attribute__((packed)) cipher_suite_t;

struct Extension_Header
{
    extension_t type;
    u_int16_t length;
} __attribute__((packed));

struct SNI
{
    u_int16_t server_name_list_len;
    u_int8_t server_name_type;
    u_int16_t server_name_len;
    char server_name[MAX_NAME_LEN];
} __attribute__((packed));

struct RecordLayer_Header
{
    content_t ContentType;      // Content Type: HandShake/Application...
    protocol_version_t Version; // TLS Version
    u_int16_t length;           // Length of Record Layer Message
} __attribute__((packed));      // Disable byte alignment while compling, otherwise RecordLayer_Header is 6 bytes

struct ClientHello
{
    handshake_t Handshake;            // Handshake Type: ClientHello/ServerHello...
    u_int8_t length[3];               // Length of Client Hello Message
    protocol_version_t ClientVersion; // TLS Version
    random_t Random;                  // Random Number
    u_int8_t session_id_len;          // Length of Session ID
    session_id_t SessionID;           // Session ID
    u_int16_t cipher_suite_len;       // Length of Cipher Suites
    cipher_suite_t CipherSuite[16];   // Cipher Suites
    u_int8_t compression_method_len;  // Length of Compresssion Methods
    u_char CompressionMethod;         // Compresssion Methods
    u_int16_t extension_len;          // Length of Compresssion Extensions
    struct
    {
        struct Extension_Header header;
    } ExtensionReserved;
    struct
    {
        struct Extension_Header header;
        struct SNI sni;
    } ExtenstionServerName;
} __attribute__((packed));

struct ServerHello
{
    handshake_t Handshake;            // Handshake Type: ClientHello/ServerHello...
    u_int8_t length[3];               // Length of Server Hello Message
    protocol_version_t ClientVersion; // TLS Version
    random_t Random;                  // Random Number
    u_int8_t session_id_len;          // Length of Session ID
    session_id_t SessionID;           // Session ID
    cipher_suite_t CipherSuite;       // Picked Cipher Suite
} __attribute__((packed));

struct RecordLayer_Header *record_layer_header;
struct ClientHello *client_hello;
struct ServerHello *server_hello;

const int RECORDLAYER_HEADER_SIZE = sizeof(struct RecordLayer_Header);
const int CLIENTHELLO_SIZE = sizeof(struct ClientHello);
const int SERVERHELLO_SIZE = sizeof(struct ServerHello);

#endif