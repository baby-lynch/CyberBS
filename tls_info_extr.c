#include "include/tls.h"

void client_hello_handler(struct ClientHello *client_hello)
{
    char *server_name;

    // Random Number
    fprintf(output, "|Random: %02x", BSWAP_32(client_hello->Random.gmt_unix_time));
    for (int i = 0; i < 28; i++)
    {
        fprintf(output, "%02x", client_hello->Random.random_bytes[i]);
    }
    fprintf(output, "\n");

    // Session ID
    fprintf(output, "|Session ID: ");
    for (int i = 0; i < 32; i++)
    {
        fprintf(output, "%02x", client_hello->SessionID.id[i]);
    }
    fprintf(output, "\n");

    // Cipher Suite
    fprintf(output, "|Cipher Suite: ");
    fprintf(output, "{ ");
    for (int i = 0; i < 16; i++)
    {
        fprintf(output, "0x%02x ", BSWAP_16(client_hello->CipherSuite[i].suite));
    }
    fprintf(output, "}");
    fprintf(output, "\n");

    // Server Name
    fprintf(output, "|Server Name: ");
    int name_len = BSWAP_16(client_hello->ExtenstionServerName.sni.server_name_len);
    
    if(name_len>0){
        server_name = (char *)malloc(sizeof(char) * (name_len+1));
        memcpy(server_name, client_hello->ExtenstionServerName.sni.server_name, name_len);
        server_name[name_len-1]='\0';  // manually terminate string
    }
    
    fprintf(output, "%s\n", server_name);
    free(server_name);
}

void server_hello_handler(struct ServerHello *server_hello)
{
    // Random Number
    fprintf(output, "|Random: %02x", BSWAP_32(server_hello->Random.gmt_unix_time));
    for (int i = 0; i < 28; i++)
    {
        fprintf(output, "%02x", server_hello->Random.random_bytes[i]);
    }
    fprintf(output, "\n");

    // Session ID
    fprintf(output, "|Session ID: ");
    for (int i = 0; i < 32; i++)
    {
        fprintf(output, "%02x", server_hello->SessionID.id[i]);
    }
    fprintf(output, "\n");

    // Cipher Suite
    fprintf(output, "|Cipher Suite: ");
    fprintf(output, "{ 0x%02x }\n", BSWAP_16(server_hello->CipherSuite.suite));

}

void tls_info_extr(u_char *payload, int data_len)
{
    /*--------------------------------------Initialization--------------------------------------*/
    record_layer_header = (struct RecordLayer_Header *)malloc(sizeof(struct RecordLayer_Header));
    client_hello = (struct ClientHello *)malloc(sizeof(struct ClientHello));
    server_hello = (struct ServerHello *)malloc(sizeof(struct ServerHello));

    /*-------------Record Layer Header------------*/
    memcpy(record_layer_header, payload, RECORDLAYER_HEADER_SIZE);

    fprintf(output, "---------------------------------------------\n");
    fprintf(output, "|Content Type: ");
    switch (record_layer_header->ContentType)
    {
    case 0x14:
        fprintf(output, "Changer Cipher Spec\n");
        break;
    case 0x15:
        fprintf(output, "Encrypted Alert\n");
        break;
    case 0x16:
        fprintf(output, "Handshake-");
        handshake_t check_byte = payload[5]; // check handshake msg type
        switch (check_byte)
        {
        case 0x01:
            fprintf(output, "Client Hello\n");
            memcpy(client_hello, payload + RECORDLAYER_HEADER_SIZE, CLIENTHELLO_SIZE);
            client_hello_handler(client_hello);
            break;
        case 0x02:
            fprintf(output, "Server Hello\n");
            memcpy(server_hello, payload + RECORDLAYER_HEADER_SIZE, SERVERHELLO_SIZE);
            server_hello_handler(server_hello);
            break;
        case 0x0b:
            fprintf(output, "Certificate\n");
            break;
        case 0x0c:
            fprintf(output, "Server Key Exchange\n");
            break;
        case 0x0d:
            fprintf(output, "Certificate Request\n");
            break;
        case 0x0e:
            fprintf(output, "Server Hello Done\n");
            break;
        case 0x0f:
            fprintf(output, "Certificate Verify\n");
            break;
        case 0x10:
            fprintf(output, "Client Key Exchange\n");
            break;
        case 0x14:
            fprintf(output, "Finished\n");
            break;
        default:
            fprintf(output, "Unknown\n");
            break;
        }
        break;
    case 0x17:
        fprintf(output, "Application Data\n");
        break;
    default:
        break;
    }

    // Version
    fprintf(output, "|Version: ");
    if (record_layer_header->Version.major == 0x03)
    {
        switch (record_layer_header->Version.minor)
        {
        case 0x00:
            fprintf(output, "SSL\n");
            break;
        case 0x01:
            fprintf(output, "TLS v1.0\n");
            break;
        case 0x02:
            fprintf(output, "TLS v1.1\n");
            break;
        case 0x03:
            fprintf(output, "TLS v1.2\n");
            break;    
        default:
            fprintf(output, "Unknown Version\n");
            break;
        }
    }
    else
    {
        fprintf(output, "Unknown Version\n");
    }

    free(record_layer_header);
    free(client_hello);
    free(server_hello);
}