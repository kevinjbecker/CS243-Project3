/// \file filter.c
/// \brief Filters IP packets based on settings in a user supplied
/// configuration file.
/// Author: Chris Dickens (RIT CS)
/// Author: kjb2503 : Kevin Becker (RIT Student)
///
/// Distribution of this file is limited
/// to Rochester Institute of Technology faculty, students and graders
/// currently enrolled in CSCI243, Mechanics of Programming.
/// Further distribution requires written approval from the
/// Rochester Institute of Technology Computer Science department.
/// The content of this file is protected as an unpublished work.
///

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "filter.h"
#include "pktUtility.h"

/// maximum line length of a configuration file
#define MAX_LINE_LEN  256

/// The type used to hold the configuration settings for a filter
typedef struct FilterConfig_S
{
    unsigned int localIpAddr;                  ///< the local IP address
    unsigned int localMask;                    ///< the address mask
    bool blockInboundEchoReq;                  ///< where to block inbound echo
    unsigned int numBlockedInboundTcpPorts;    ///< count of blocked ports
    unsigned int* blockedInboundTcpPorts;      ///< array of blocked ports
    unsigned int numBlockedIpAddresses;        ///< count of blocked addresses
    unsigned int* blockedIpAddresses;          ///< array of blocked addresses
} FilterConfig;


/// Parses the remainder of the string last operated on by strtok
/// and converts each octet of the ASCII string IP address to an
/// unsigned integer value.
/// @param ipAddr The destination into which to store the octets
/// @pre caller must have first called strtok to set its pointer.
/// @post ipAddr contains the ip address found in the string
static void parse_remainder_of_string_for_ip(unsigned int* ipAddr)
{
    char* pToken;

    pToken = strtok(NULL, ".");
    sscanf(pToken, "%u", &ipAddr[0]);
    pToken = strtok(NULL, ".");
    sscanf(pToken, "%u", &ipAddr[1]);
    pToken = strtok(NULL, ".");
    sscanf(pToken, "%u", &ipAddr[2]);
    pToken = strtok(NULL, "/");
    sscanf(pToken, "%u", &ipAddr[3]);
}


/// Checks if an IP address is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param addr The IP address that is to be checked
/// @return True if the IP address is to be blocked
static bool block_ip_address(FilterConfig* fltCfg, unsigned int addr)
{
    for(unsigned int i = 0; i < fltCfg->numBlockedIpAddresses; ++i)
    {
        // if the IP Address is set to be blocked, we return tru to alert that
        if(fltCfg->blockedIpAddresses[i] == addr)
            return true;
    }
    // if we get here we're okay we can allow it through
    return false;
}


/// Checks if a TCP port is listed as blocked by the supplied filter.
/// @param fltCfg The filter configuration to use
/// @param port The TCP port that is to be checked
/// @return True if the TCP port is to be blocked
static bool block_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port)
{
    // goes through each tcp port and checks if it needs to be blocked
    for(unsigned int i = 0; i < fltCfg->numBlockedInboundTcpPorts; ++i)
    {
        // if it does need to be blocked, return true
        if(fltCfg->blockedInboundTcpPorts[i] == port)
            return true;
    }
    // otherwise false
    return false;
}


/// Checks if a packet is coming into the network from the external world. Uses
/// the localMask in the supplied filter configuration to compare the srcIpAddr
/// and dstIpAddr to the localIpAddr supplied in the filter configuration. If the
/// dstIpAddr is on the same network as the localIpAddr, and the srcIpAddr is not
/// on the same network as the localIpAddr then the packet is inbound.
/// @param fltCfg The filter configuration to use
/// @param srcIpAddr The source IP address of a packet
/// @param dstIpAddr The destination IP address of a packet
static bool packet_is_inbound(FilterConfig* fltCfg, unsigned int srcIpAddr, unsigned int dstIpAddr)
{
//    unsigned int localIpAddr;      ///< the local IP address
//    unsigned int localMask;        ///< the address mask
    unsigned int localIpMasked = fltCfg->localIpAddr & fltCfg->localMask;
    unsigned int srcIpMasked = srcIpAddr & fltCfg->localMask;
    unsigned int dstIpMasked = dstIpAddr & fltCfg->localMask;

    // packet is only inbound if dst is on local network and src is not
    return (dstIpMasked == localIpMasked && srcIpMasked != localIpMasked);
}


/// Adds the specified IP address to the array of blocked IP addresses in the
/// specified filter configuration. This requires allocating additional memory
/// to extend the length of the array that holds the blocked IP addresses.
/// @param fltCfg The filter configuration to which the IP address is added
/// @param ipAddr The IP address that is to be blocked
static void add_blocked_ip_address(FilterConfig* fltCfg, unsigned int ipAddr)
{
    // gets the current size and adds 1 (we are attempting to add a new one)
    unsigned int newSize = fltCfg->numBlockedIpAddresses+1;
    // reallocates the blockedIpAddresses array
    fltCfg->blockedIpAddresses = realloc(fltCfg->blockedIpAddresses,
                                         sizeof(unsigned int) * newSize);
    fltCfg->numBlockedIpAddresses = newSize;
    // sets in place our new IP address
    fltCfg->blockedIpAddresses[newSize - 1] = ipAddr;
}


/// Adds the specified TCP port to the array of blocked TCP ports in the
/// specified filter configuration. This requires allocating additional
/// memory to extend the length of the array that holds the blocked ports.
/// @param fltCfg The filter configuration to which the TCP port is added
/// @param port The TCP port that is to be blocked
static void add_blocked_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port)
{
    // gets the current size and adds 1 (we are attempting to add a new one)
    unsigned int newSize = fltCfg->numBlockedInboundTcpPorts+1;
    // reallocates the blockedInboundTcpPorts array
    fltCfg->blockedInboundTcpPorts = realloc(fltCfg->blockedInboundTcpPorts,
                                             sizeof(unsigned int) * newSize);

    fltCfg->numBlockedInboundTcpPorts = newSize;
    // sets in place our new port
    fltCfg->blockedInboundTcpPorts[newSize - 1] = port;
}


/// Creates an instance of a filter by allocating memory for a FilterConfig
/// and initializing its member variables.
/// @return A pointer to the new filter
IpPktFilter create_filter(void)
{
    FilterConfig* filter = NULL;
    // allocates enough space for filter
    filter = malloc(sizeof(FilterConfig));

    // checks to make sure malloc was successful
    if(filter == NULL)
    {
        perror("Error creating filter");
        return NULL;
    }

    // if we get here malloc was successful; we can set defaults
    filter->localIpAddr = 0;
    filter->localMask = 0;
    filter->blockInboundEchoReq = false;
    filter->numBlockedInboundTcpPorts = 0;
    filter->blockedInboundTcpPorts = NULL;
    filter->numBlockedIpAddresses = 0;
    filter->blockedIpAddresses = NULL;

    // return our newly created filter
    return (IpPktFilter) filter;
}


/// Destroys an instance of a filter by freeing all of the dynamically
/// allocated memory associated with the filter.
/// @param filter The filter that is to be destroyed
void destroy_filter(IpPktFilter filter)
{
    FilterConfig* fltCfg = filter;

    // frees our arrays if they need to be
    if(fltCfg->blockedInboundTcpPorts != NULL)
        free(fltCfg->blockedInboundTcpPorts);
    if(fltCfg->blockedIpAddresses != NULL)
        free(fltCfg->blockedIpAddresses);

    // we've now free'd everything that needs to be, we can now free filter
    free(filter);
}


/// Configures a filter instance using the specified configuration file.
/// Reads the file line by line and uses strtok, strcmp, and sscanf to
/// parse each line.  After each line is successfully parsed the result
/// is stored in the filter.  Blank lines are skipped.  When the end of
/// the file is encountered, the file is closed and the function returns.
/// @param filter The filter that is to be configured
/// @param filename The full path/filename of the configuration file that
/// is to be read.
/// @return True when successful
bool configure_filter(IpPktFilter filter, char* filename)
{
    // buffer of 256 length (max line in the file)
    char buf[MAX_LINE_LEN];
    // the file pointer to the configuration file
    FILE* pFile;
    // pToken?
    char* pToken;
    // success?
    char* success;

    // boolean to determine if the configuration was valid or not
    bool validConfig = false;

    pFile = fopen(filename, "r");
    if(pFile == NULL)
    {
        perror("Error opening configuration file");
        return false;
    }

    // keeps going until we're at the end of file
    while(!feof(pFile))
    {
        if(fgets(buf, MAX_LINE_LEN, pFile)!=NULL)
        {
            fputs("Error, reading configuration file failed", stderr);
            break;
            // if we hit an erro we need to break
        }

        // only process if not an empty line
        if(buf[0] != '\n')
        {
            validConfig = true;
            // process
        }
    }

    // closes the file before we exit
    fclose(pFile);

    if(validConfig == false)
        fputs("Error, configuration file must set LOCAL_NET", stderr);

    return validConfig;
}


/// Uses the settings specified by the filter instance to determine
/// if a packet should be allowed or blocked.  The source and
/// destination IP addresses are extracted from each packet and
/// checked using the block_ip_address helper function. The IP protocol
/// is extracted from the packet and if it is ICMP or TCP then
/// additional processing occurs. This processing blocks inbound packets
/// set to blocked TCP destination ports and inbound ICMP echo requests.
/// @param filter The filter configuration to use
/// @param pkt The packet to examine
/// @return True if the packet is allowed by the filter. False if the packet
/// is to be blocked
bool filter_packet(IpPktFilter filter, unsigned char* pkt)
{
    FilterConfig* fltCfg = (FilterConfig*)filter;
    unsigned int srcIpAddr = ExtractSrcAddrFromIpHeader(pkt);
    unsigned int dstIpAddr = ExtractDstAddrFromIpHeader(pkt);
    unsigned int IpProtocol = ExtractIpProtocol(pkt);
    bool packetInbound = packet_is_inbound(fltCfg, srcIpAddr, dstIpAddr);

    // initial check on the ip's themselves
    if(block_ip_address(fltCfg, srcIpAddr) || block_ip_address(fltCfg, dstIpAddr))
        return false;

    // if we get here we might need to do more processing
    switch(IpProtocol)
    {
        case IP_PROTOCOL_ICMP:
            /* if packet is inbound, ICMP is echo request and we want to block
               them, return false, we don't want it through */
            if (packetInbound &&
                ExtractIcmpType(pkt) == ICMP_TYPE_ECHO_REQ &&
                fltCfg->blockInboundEchoReq)
                return false;
            else
                return true;
        case IP_PROTOCOL_TCP:
            // if packet is inbound and the TCP port should be blocked,
            // return false
            if (packetInbound &&
                block_inbound_tcp_port(fltCfg, ExtractTcpDstPort(pkt)))
                return false;
            else
                return true;
        default:
            return true;
    }
}
