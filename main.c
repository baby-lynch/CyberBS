#include "header.h"

int main(int argc, char *argv[])
{
    FILE *fp;
    const char *FILEPATH = "./pcap/instagram.pcap";

    int pkt_no = 0;             // Packet sequence number
    int pkt_offset;             // Packet offset
    int HEADER_LEN;             // Length of all headers
    int DATA_LEN;               // Lenght of payload
    int actual_tcp_header_size; // TCP header length read from its header (with Options tailed)
    char src_ip[STRSIZE], dst_ip[STRSIZE];
    u_char Payload[BUFSIZE];
    u_char check_bytes[2];    // check if the packet belongs to TLS; 0x14<=check_bytes[0]<=0x17, check_bytes[2]=0x03
    u_char protocol_above_ip; // determine UDP or TCP protocol

    /*--------------------------------------Initialization--------------------------------------*/
    file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
    pkt_header = (struct pcap_packet_header *)malloc(sizeof(struct pcap_packet_header));
    eth_header = (struct Ethernet_Header *)malloc(sizeof(struct Ethernet_Header));
    ipv4_header = (struct IPv4_Header *)malloc(sizeof(struct IPv4_Header));
    ipv6_header = (struct IPv6_Header *)malloc(sizeof(struct IPv6_Header));
    tcp_header = (struct TCP_Header *)malloc(sizeof(struct TCP_Header));

    /*-----------------------------Read packets one by one from PCAP-----------------------------*/
    if ((fp = fopen(FILEPATH, "r")) == NULL)
    {
        printf(">> error: can not open pcap file\n");
        exit(0);
    }

    if ((output = fopen("output.txt", "w +")) == NULL)
    {
        printf(">> error: can not open output file\n");
        exit(0);
    }

    pkt_offset = 24; // PCAP 24 bytes file header

    while (!fseek(fp, pkt_offset, SEEK_SET))
    {
        HEADER_LEN = 0; // reset header length
        pkt_no++;
        memset(pkt_header, 0, PACKET_HEADER_SIZE);
        if (fread(pkt_header, PACKET_HEADER_SIZE, 1, fp) != 1)
        {
            printf(">> info: read end of pcap file\n");
            break;
        }
        pkt_offset += PACKET_HEADER_SIZE + pkt_header->caplen; // offset of next packet

        fprintf(output, " _______________P A C K E T %d_______________\n", pkt_no);

        /*-------------Ethernet header-------------*/
        HEADER_LEN += ETHERNET_HEADER_SIZE;
        memset(eth_header, 0, ETHERNET_HEADER_SIZE);
        fread(eth_header, ETHERNET_HEADER_SIZE, 1, fp);

        /*----------------IP header----------------*/
        switch (BSWAP_16(eth_header->Eth_Type))
        {
        case 0x0800:
            /*-------------IPv4 header-------------*/
            HEADER_LEN += IPv4_HEADER_SIZE;
            memset(ipv4_header, 0, IPv4_HEADER_SIZE);
            fread(ipv4_header, IPv4_HEADER_SIZE, 1, fp);
            inet_ntop(AF_INET, (void *)&(ipv4_header->Src_IP), src_ip, 16);
            inet_ntop(AF_INET, (void *)&(ipv4_header->Dst_IP), dst_ip, 16);
            fprintf(output, "|Source IPv4 Address: %s\n", src_ip);
            fprintf(output, "|Destination IPv4 Address: %s\n", dst_ip);
            protocol_above_ip = ipv4_header->Protocol;
            break;
        case 0x86dd:
            /*-------------IPv6 header-------------*/
            HEADER_LEN += IPv6_HEADER_SIZE;
            memset(ipv6_header, 0, IPv6_HEADER_SIZE);
            fread(ipv6_header, IPv6_HEADER_SIZE, 1, fp);
            inet_ntop(AF_INET6, (void *)&(ipv6_header->Src_IP), src_ip, 46);
            inet_ntop(AF_INET6, (void *)&(ipv6_header->Dst_IP), dst_ip, 46);
            fprintf(output, "|Source IPv6 Address: %s\n", src_ip);
            fprintf(output, "|Destination IPv6 Address: %s\n", dst_ip);
            protocol_above_ip = ipv6_header->Next_Header;
        default:
            break;
        }

        switch (protocol_above_ip)
        {
        case 0x06:
            /*-------------TCP header-------------*/
            memset(tcp_header, 0, TCP_HEADER_SIZE);
            fread(tcp_header, TCP_HEADER_SIZE, 1, fp);
            // curse backwards for the sake of reading HEADER LENGTH bytes from the beginning of tcp header
            fseek(fp, -TCP_HEADER_SIZE, SEEK_CUR);
            actual_tcp_header_size = High_4(tcp_header->HeaderLen) * 4;
            // tcp header length is counted PER 4 BTYE !!!
            HEADER_LEN += actual_tcp_header_size;
            fprintf(output, "|TCP Source Port: %d\n", ntohs(tcp_header->SrcPort));
            fprintf(output, "|TCP Destination Port: %d\n", ntohs(tcp_header->DstPort));

            /*-------------TCP Payload-------------*/
            DATA_LEN = pkt_header->caplen - HEADER_LEN;
            fseek(fp, actual_tcp_header_size, SEEK_CUR);
            fread(Payload, DATA_LEN, 1, fp);
            fprintf(output, "|Payload Size: %d bytes\n", DATA_LEN);
            if (DATA_LEN > 0)
            {
                memcpy(check_bytes, Payload, 2);
                // determine whether a packet belongs to TLS
                if (check_bytes[0] >= 0x14 && check_bytes[0] <= 0x17)
                {
                    if (check_bytes[1] == 0x03)
                    {
                        fprintf(output, "|Packet Type: TLS\n");
                        // extract information from TLS
                        tls_info_extr(Payload, DATA_LEN);
                    }
                    else
                    {
                        fprintf(output, "|Packet Type: TCP\n");
                    }
                }
                else
                {
                    fprintf(output, "|Packet Type: TCP\n");
                }
            }
            else
            {
                fprintf(output, "|Packet Type: TCP\n");
            }
            fprintf(output, "\n");
            break;
        case 0x11:
            /*-------------UDP header-------------*/
            fprintf(output, "|Packet Type: UDP\n\n");
            continue; // ignore UDP packet
            break;
        default:
            break;
        }
    }

    fclose(fp);
    fclose(output);
    free(file_header);
    free(pkt_header);
    free(eth_header);
    free(ipv4_header);
    free(ipv6_header);
    free(tcp_header);
}
