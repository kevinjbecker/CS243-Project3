/// \file filter.c
/// \brief Filters IP packets based on settings in a user supplied
/// configuration file.
/// Author: Chris Dickens (RIT CS)
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
   unsigned int localIpAddr;    ///< the local IP address
   unsigned int localMask;      ///< the address mask
   bool blockInboundEchoReq;    ///< where to block inbound echo
   unsigned int numBlockedInboundTcpPorts;   ///< count of blocked ports
   unsigned int* blockedInboundTcpPorts;     ///< array of blocked ports
   unsigned int numBlockedIpAddresses;       ///< count of blocked addresses
   unsigned int* blockedIpAddresses;         ///< array of blocked addresses
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
      if(fltCfg->blockedIpAddresses[i] = addr)
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
   for(unsigned int i = 0; i < fltCfg->numBlockedInboundTcpPorts; ++i)
   {
      if(fltCfg->blockedInboundTcpPorts[i] == port)
         return true;
   }
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
//   unsigned int localIpAddr;    ///< the local IP address
//   unsigned int localMask;      ///< the address mask
// TODO: continue this shit because it's confusing
   return (fltCfg->localIpAddr == dstIpAddr)
}


/// Adds the specified IP address to the array of blocked IP addresses in the
/// specified filter configuration. This requires allocating additional memory
/// to extend the length of the array that holds the blocked IP addresses.
/// @param fltCfg The filter configuration to which the IP address is added
/// @param ipAddr The IP address that is to be blocked
static void add_blocked_ip_address(FilterConfig* fltCfg, unsigned int ipAddr)
{

//TODO: student implements add_blocked_ip_address()

}


/// Adds the specified TCP port to the array of blocked TCP ports in the
/// specified filter configuration. This requires allocating additional
/// memory to extend the length of the array that holds the blocked ports.
/// @param fltCfg The filter configuration to which the TCP port is added
/// @param port The TCP port that is to be blocked
static void add_blocked_inbound_tcp_port(FilterConfig* fltCfg, unsigned int port)
{

//TODO: student implements add_blocked_inbound_tcp_port()

}


/// Creates an instance of a filter by allocating memory for a FilterConfig
/// and initializing its member variables.
/// @return A pointer to the new filter
IpPktFilter create_filter(void)
{
/*
typedef struct FilterConfig_S
{
   unsigned int localIpAddr;    ///< the local IP address
   unsigned int localMask;      ///< the address mask
   bool blockInboundEchoReq;    ///< where to block inbound echo
   unsigned int numBlockedInboundTcpPorts;   ///< count of blocked ports
   unsigned int* blockedInboundTcpPorts;     ///< array of blocked ports
   unsigned int numBlockedIpAddresses;       ///< count of blocked addresses
   unsigned int* blockedIpAddresses;         ///< array of blocked addresses
} FilterConfig;
*/
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
   return (IpPktFilter*)filter;
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
   char buf[MAX_LINE_LEN];
   FILE* pFile;
   char* pToken;
   char* success;
   bool  validConfig = false;

//TODO: student implements configure_filter()

   pFile = fopen(filename, "r");
   if(pFile == NULL)
   {
      printf("ERROR: invalid config file\n");
      return false;
   }

   if(validConfig == false)
   {
      fprintf(stderr, "Error, configuration file must set LOCAL_NET\n");
   }
 
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
/// @param pkt The packet to exame
/// @return True if the packet is allowed by the filter. False if the packet
/// is to be blocked
bool filter_packet(IpPktFilter filter, unsigned char* pkt)
{
   unsigned int srcIpAddr;
   unsigned int dstIpAddr;
   FilterConfig* fltCfg = (FilterConfig*)filter;

//TODO: student implements filter_packet()

  return true;
}

