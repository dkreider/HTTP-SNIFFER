#include "main.h"

void outbound_url(char *packet_data, UINT16 payload_len)
{
	static const char get_request[] = "GET /";
	static const char post_request[] = "POST /";
	static const char http_host[] = "HTTP/1.1\r\nHost: ";
	char domain[MAXURL];
	char uri[MAXURL];
	UINT16 i = 0, j;

	
	// Verify that the packet contains HTTP requests.
	if (payload_len <= sizeof(post_request) + sizeof(http_host)) {
		printf("The packet data is less than size of HTTP requests.\n");
	}

	else if (strncmp(packet_data, get_request, sizeof(get_request) - 1) == 0) {
		i += sizeof(get_request) - 1;
	}

	else if (strncmp(packet_data, post_request, sizeof(post_request) - 1) == 0) {
		i += sizeof(post_request) - 1;
	}

	else {
		printf("Outgoing packet does not contain HTTP GET or POST request.\n");
	}

}
