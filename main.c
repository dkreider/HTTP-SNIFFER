/**********
Daniel Kreider 04/19/16 - HTTP SNIFFER 0.0.1

Simple HTTP Sniffer that displays simple info like destination IP and port for all outgoing 
connections on ports 53, 80 and 443.

Plans are to amplify as I get time to show things like host-name lookups, HTTP GET requests, etc...

**********/

#include "main.h"


int main()
{
    HANDLE handle;
    WINDIVERT_ADDRESS addr;
	PWINDIVERT_IPHDR ip_header; 
	PWINDIVERT_IPV6HDR ipv6_header;
	PWINDIVERT_ICMPHDR icmp_header;
	PWINDIVERT_ICMPV6HDR icmpv6_header;
	PWINDIVERT_TCPHDR tcp_header;
	PWINDIVERT_UDPHDR udp_header;
    unsigned char packet[MAXBUF];
    UINT packet_len;
	UINT payload_len;
	PVOID payload;

    // Open the Divert device:
    handle = WinDivertOpen(
		"outbound && "
		"(tcp.DstPort == 53 or tcp.DstPort == 80 or tcp.DstPort == 443)",
		0, 0, 0
	);

    if (handle == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        exit(EXIT_FAILURE);
    }
    printf("OPENED WinDivert\n");

    // Main loop:
    while (TRUE)
    {
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len))
		{
			fprintf(stderr, "WARNING: failed to read packet (%d)\n",
				GetLastError());
			continue;
		}
		else
			printf("Read a packet\n");

		// Scan packet.
		WinDivertHelperParsePacket(packet, packet_len, &ip_header,
			NULL, NULL, NULL, &tcp_header,
			&udp_header, &payload, &payload_len);

		// Determine destination.
		if (ip_header != NULL)
		{
			UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;

			printf("Outbound packet headed to %u.%u.%u.%u ",
				dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
		}

		// Inspect TCP packets.
		if (tcp_header != NULL)
		{
			printf("on port %u.\n", ntohs(tcp_header->DstPort));

			printf("TCP state is ");

			if (tcp_header->Fin) {
				printf("FIN\n");
			}

			if (tcp_header->Rst) {
				printf("RST\n");
			}

			if (tcp_header->Urg) {
				printf("URG\n");
			}

			if (tcp_header->Syn) {
				printf("SYN\n");
			}

			if (tcp_header->Psh) {
				printf("PSH\n");
			}

			if (tcp_header->Ack) {
				printf("ACK\n");
			}
		}

		// Inspect outgoing request further to reveal requested URL.
		outbound_url(payload, (UINT16)payload_len);


        // Send packet
		if (!WinDivertSend(handle, packet, packet_len, &addr, NULL))
		{
			fprintf(stderr, "warning: failed to reinject packet (%d)\n",
				GetLastError());
		}
		else
			printf("Packet re-injected successfully.\n");
        }
    
}

