#include "header.h"

int main(int argc, char *argv[])
{
    FILE *fp;
    const char *FILEPATH = "./pcap/baidu/All.pcap";

    int pkt_no = 0;                                                           // Packet sequence number
    int pkt_offset;                                                           // Packet offset
    int HEADER_LEN = ETHERNET_HEADER_SIZE + IP_HEADER_SIZE + TCP_HEADER_SIZE; // Length of all headers
    int DATA_LEN;                                                             // Lenght of payload
    char src_ip[STRSIZE], dst_ip[STRSIZE];
    u_char Payload[BUFSIZE];
    u_char check_bytes[2]; // check if the packet is TCP or TLS; 0x14<=check_bytes[0]<=0x17, check_bytes[2]=0x03

    /*--------------------------------------Initialization--------------------------------------*/
    file_header = (struct pcap_file_header *)malloc(sizeof(struct pcap_file_header));
    pkt_header = (struct pcap_packet_header *)malloc(sizeof(struct pcap_packet_header));
    // eth_header = (Ethernet_Header *)malloc(sizeof(Ethernet_Header));
    ip_header = (struct IP_Header *)malloc(sizeof(struct IP_Header));
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

    while (fseek(fp, pkt_offset, SEEK_SET) == 0)
    {
        pkt_no++;
        memset(pkt_header, 0, PACKET_HEADER_SIZE);
        if (fread(pkt_header, 16, 1, fp) != 1)
        {
            printf(">> info: read end of pcap file\n");
            break;
        }
        pkt_offset += 16 + pkt_header->caplen; // offset of next packet

        fprintf(output, " _______________P A C K E T %d_______________\n", pkt_no);

        /*-------------Ethernet header-------------*/
        // memset(eth_header, 0, ETHERNET_HEADER_SIZE);
        // fread(eth_header, ETHERNET_HEADER_SIZE, 1, fp);
        fseek(fp, 14, SEEK_CUR); // ethernet header is ignored

        /*-------------IP header-------------*/
        memset(ip_header, 0, IP_HEADER_SIZE);
        fread(ip_header, IP_HEADER_SIZE, 1, fp);
        inet_ntop(AF_INET, (void *)&(ip_header->Src_IP), src_ip, 16);
        inet_ntop(AF_INET, (void *)&(ip_header->Dst_IP), dst_ip, 16);
        fprintf(output, "|Source IP Address: %s\n", src_ip);
        fprintf(output, "|Destination IP Address: %s\n", dst_ip);

        /*-------------TCP header-------------*/
        memset(tcp_header, 0, TCP_HEADER_SIZE);
        fread(tcp_header, TCP_HEADER_SIZE, 1, fp);
        fprintf(output, "|Source Port: %d\n", ntohs(tcp_header->SrcPort));
        fprintf(output, "|Destination Port: %d\n", ntohs(tcp_header->DstPort));

        /*-------------Payload-------------*/
        DATA_LEN = pkt_header->caplen - HEADER_LEN;
        fread(Payload, DATA_LEN, 1, fp);
        fprintf(output, "|Payload Size: %d bytes\n", DATA_LEN);
        if (DATA_LEN > 0)
        {
            memcpy(check_bytes, Payload, 2);
            if (check_bytes[0] >= 0x14 && check_bytes[0] <= 0x17) // determine whether a packet belongs to TLS
            {
                if (check_bytes[1] == 0x03)
                {
                    fprintf(output, "|Packet Type: TLS\n");
                    tls_info_extr(Payload, DATA_LEN); // extract information from TLS
                }
                else
                {
                    fprintf(output, "|Packet Type: TCP\n\n");
                }
            }
            else
            {
                fprintf(output, "|Packet Type: TCP\n\n");
            }
        }
        else
        {
            fprintf(output, "|Packet Type: TCP\n\n");
        }
    }

    fclose(fp);
    fclose(output);
    free(file_header);
    free(pkt_header);
    free(ip_header);
    free(tcp_header);

    printf("argc: %d\n", argc);
    for (int i = 0; i < argc; i++)
    {
        printf("argv[%d]:%s\n", i + 1, argv[i]);
    }
    return 0;
}
