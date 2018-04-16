/// \file firewall.c
/// \brief Reads IP packets from a named pipe, examines each packet,
/// and writes allowed packets to an output named pipe.
/// Author: Chris Dickens (RIT CS)
/// Author: Ben K Steele (RIT CS)
/// Author: kjb2503 : Kevin Becker (RIT Student)
///
/// Distribution of this file is limited
/// to Rochester Institute of Technology faculty, students and graders
/// currently enrolled in CSCI243, Mechanics of Programming.
/// Further distribution requires written approval from the
/// Rochester Institute of Technology Computer Science department.
/// The content of this file is protected as an unpublished work.

/// posix needed for signal handling
#define _BSD_SOURCE

#include <sys/wait.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>      /* interrupt signal stuff is from here */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>      /* read library call comes from here */
#include "filter.h"

/// maximum packet length (ipv4)
#define MAX_PKT_LENGTH 2048

/// Type used to control the mode of the firewall
typedef enum FilterMode_E
{
    MODE_BLOCK_ALL,
    MODE_ALLOW_ALL,
    MODE_FILTER
} FilterMode;


/// Pipes_S structure maintains the stream pointers.
typedef struct Pipes_S
{
    FILE * in_pipe;                  ///< input pipe stream
    FILE * out_pipe;                 ///< output pipe stream
} Pipes_T;

/// FWSpec_S structure holds firewall configuration, filter and I/O.
typedef struct FWSpec_S
{
    char * config_file;              ///< name of the firewall config file
    char * in_file;                  ///< name of input pipe
    char * out_file;                 ///< name of output pipe
    IpPktFilter filter;              ///< pointer to the filter configuration
    Pipes_T pipes;                   ///< pipes is the stream data storage.
} FWSpec_T;

/// fw_spec is the specification data storage for the firewall.
static FWSpec_T fw_spec;

/// MODE controls the mode of the firewall. main writes it and filter reads it.
static volatile FilterMode MODE = MODE_FILTER;

/// NOT_CANCELLED flag written by main and read by the thread.
static volatile int NOT_CANCELLED = 1;

/// thread object for the filter thread
static pthread_t tid_filter;

/// thread specific data key for pthread cleanup after cancellation.
static pthread_key_t tsd_key;


/// Open the input and output streams used for reading and writing packets.
/// @param spec_ptr structure contains input and output stream names.
/// @return true if successful
static bool open_pipes(FWSpec_T *spec_ptr)
{
    spec_ptr->pipes.in_pipe = fopen(spec_ptr->in_file, "rb");
    if(spec_ptr->pipes.in_pipe == NULL)
    {
        fprintf(stderr, "fw: ERROR: failed to open pipe %s.\n", spec_ptr->in_file);
        return false;
    }
    spec_ptr->pipes.out_pipe = fopen(spec_ptr->out_file, "wb");
    if(spec_ptr->pipes.out_pipe == NULL)
    {
        fprintf(stderr, "fw: ERROR: failed to open pipe %s.\n", spec_ptr->out_file);
        return false;
    }
    return true;
}


/// close the streams. Call this once at the end of a simulation.
/// @param pipetab pointer to the I/O streams
void close_pipes(Pipes_T *pipetab) {

    if(pipetab->in_pipe != NULL)
    {
        fclose(pipetab->in_pipe);
        pipetab->in_pipe = NULL;
    }

    if(pipetab->out_pipe != NULL)
    {
        fclose(pipetab->out_pipe);
        pipetab->out_pipe = NULL;
    }
}


/// The tsd_destroy function cleans up thread specific data (TSD).
/// The spawning thread passes this function into pthread_key_create before
/// starting the thread.
/// The thread instance calls pthread_setspecific(key, (void *) value)
/// where value is the dynamic thread specific data.
/// When the thread exits, infrastructure calls the destroy function to
/// dispose of the TSD.
/// @param tsd_data pointer to thread specific data allocations to free/close
void tsd_destroy(void * tsd_data) {

    FWSpec_T *fw_spec = (FWSpec_T *)tsd_data;
    puts("fw: thread destructor is deleting filter data.");
    if (fw_spec->filter)
    {
        destroy_filter(fw_spec->filter);
        fw_spec->filter = NULL;
    }
    puts("fw: thread destructor is closing pipes.");
    close_pipes(&fw_spec->pipes);
}

/// signal handler passes signal information to the subordinate thread so
/// that the thread can gracefully terminate and clean up.
/// @param signum signal that was received by the main thread.
static void sig_handler(int signum)
{
    if (signum == SIGHUP) {
        NOT_CANCELLED = 0;
        puts("\nfw: received Hangup request. Cancelling...");
        pthread_cancel(tid_filter);                // cancel on signal to hangup
    }
}


/// init_sig_handlers initializes sigaction and installs signal handlers.
static void init_sig_handlers()
{
    struct sigaction signal_action;               // define sig handler table

    signal_action.sa_flags = 0;                   // linux lacks SA_RESTART
    sigemptyset(&signal_action.sa_mask);          // no masked interrupts
    signal_action.sa_handler = sig_handler;       // insert handler function

    sigaction(SIGHUP, &signal_action, NULL);      // for HangUP from fwSim
    return;
} // init_sig_handlers


/// Read an entire IP packet from the input pipe
/// @param in_pipe the binary input file stream
/// @param buf Destination buffer for storing the packet
/// @param buflen The length of the supplied destination buffer
/// @return length of the packet or -1 for error
static int read_packet(FILE * in_pipe, unsigned char* buf, int buflen)
{
    int numRead = 0;
    int numBytes = -1;
    // reads in the number of bytes we should read in
    if(fread(&numBytes, sizeof(int), 1, in_pipe) != 1)
    {
        fprintf(stderr, "fw: ERROR: error reading packet size.\n");
        return -1;
    }

    // if the number of bytes for this packet is too large, we need to abort
    if(numBytes > buflen)
    {
        // alerts that an incoming packet is too big
        fprintf(stderr, "fw: ERROR: packet is too large.\n");
        //return -1 as failure
        return -1;
    }

    // reads in the number of bytes specified in numBytes
    numRead = fread(buf, sizeof(unsigned char), numBytes, in_pipe);
    // returns -1 if something went wrong, otherwise the number of bytes read in
    if(numBytes != numRead)
    {
        // prints that something went wrong
        fprintf(stderr, "fw: ERROR: numBytes != numRead (%d != %d).\n", numBytes, numRead);
        // returns -1
        return -1;
    }
    // returns the number of read bytes
    return numRead;
}


/// Runs as a thread and handles each packet. It is responsible
/// for reading each packet in its entirety from the input pipe,
/// filtering it, and then writing it to the output pipe. The
/// single void* parameter matches what is expected by pthread.
/// return value and parameter must match those expected by pthread_create.
/// @param args pointer to an FWSpec_T structure
/// @return pointer to static exit status value which is 0 on success
static void * filter_thread(void* args)
{
    // sets the tsd specific destructor
    // pthread_setspecific(tsd_key, (void *)&fw_spec);

    // a few variables needed for running
    unsigned char pktBuf[MAX_PKT_LENGTH];
    //bool success = false;
    int length;
    static int status = EXIT_FAILURE; // static for return persistence
    status = EXIT_FAILURE; // reset status
    // our firewall specification (need to case since it is void)
    FWSpec_T * spec_p = (FWSpec_T *) args;
    while(NOT_CANCELLED &&
          ((length = read_packet(spec_p->pipes.in_pipe, pktBuf, MAX_PKT_LENGTH)) != -1))
    {
        // determines if the packet should be let through or not
        if((MODE == MODE_FILTER && filter_packet(spec_p->filter, pktBuf)) ||
            MODE == MODE_ALLOW_ALL)
        {
            // writes the size of the packet
            if(fwrite(&length, sizeof(int), 1, spec_p->pipes.out_pipe) != 1)
                fprintf(stderr, "fw: ERROR: there was an issue writing packet size.\n");
            // writes the actual packet
            if(fwrite(pktBuf, length, 1, spec_p->pipes.out_pipe) != 1)
                fprintf(stderr, "fw: ERROR: there was an issue writing packet.\n");

            // flushes the output for fwSim to read
            fflush(spec_p->pipes.out_pipe);

            /* A bit of reasoning behind this next sleep, since NOT_CANCELLED might
               be changed between the flush and the next fread, there is a
               possibility for the thread to be blocking before NOT_CANCELLED is
               set.  Thus, sleeping for a tiny bit will allow for NOT_CANCELLED to
               be set in time for the loop to exit. */
            usleep(100);
        }
    }
    // end of thread is never reached when there is a cancellation.
    puts("fw: thread is deleting filter data.");
    tsd_destroy((void *)spec_p);

    // changes status to be success if we broke the loop successfully
    if(!NOT_CANCELLED && length != -1)
        status = EXIT_SUCCESS;

    printf("fw: thread returning. status: %d\n", status);

    pthread_exit(&status);
}


/// Displays a prompt to stdout and menu of commands that a user can choose
static void display_menu(void)
{
    // prints an options menu
    puts("\n\n1. Block All");
    puts("2. Allow All");
    puts("3. Filter");
    puts("0. Exit");
    printf("> ");
    fflush(stdout);
}

/// The firewall main function creates a filter and launches filtering thread.
/// Then it handles user input with a simple menu and prompt.
/// When the user requests and exit, the main cancels and joins the thread
/// before exiting itself.
/// Run this program with the configuration file as a command line argument.
/// @param argc Number of command line arguments; 1 expected
/// @param argv Command line arguments; name of the configuration file
/// @return EXIT_SUCCESS or EXIT_FAILURE
int main(int argc, char* argv[])
{
    int command;
    bool done = false;

    // print usage message if no arguments
    if(argc < 2)
    {
        fprintf(stderr, "usage: %s configFileName\n", argv[0]);
        return EXIT_FAILURE;
    }

    // initializes the signal handlers
    init_sig_handlers();

    // sets the three filename strings
    fw_spec.config_file = argv[1];
    fw_spec.in_file = "ToFirewall";
    fw_spec.out_file = "FromFirewall";
    // creates and configures the filter
    fw_spec.filter = create_filter();
    configure_filter(fw_spec.filter, fw_spec.config_file);

    // opens the two named pipes (how do made faster??)
    if(!open_pipes(&fw_spec))
    {
        close_pipes(&fw_spec.pipes);
        destroy_filter(&fw_spec.filter);
        return EXIT_FAILURE;
    }

    // prints that we are going to start the listener thread
    puts("fw: starting filter thread.");
    // creates a pthread key
    pthread_key_create(&tsd_key, tsd_destroy);
    // starts the filter thread
    pthread_create(&tid_filter, NULL, filter_thread, (void *)&fw_spec);

    // thread is started, display the menu now
    display_menu();
    // keeps looping until the user says it needs to stop
    while(!done)
    {
        // attempts to read in user input, prints an error if an issue occurs
        if(scanf("%d", &command) != 1)
            fprintf(stderr, "fw: ERROR: error reading user input, skipping.\n");
        switch(command)
        {
            case 0:
                // exit command received, exiting
                done = true;
                break;
            case 1:
                puts("fw: blocking all packets");
                MODE = MODE_BLOCK_ALL;
                break;
            case 2:
                puts("fw: allowing all packets");
                MODE = MODE_ALLOW_ALL;
                break;
            case 3:
                puts("fw: filtering packets");
                MODE = MODE_FILTER;
                break;
        }

        // prints out a new prompt character
        printf("> ");
        fflush(stdout);
    }

    // when we get here we are exiting
    puts("Exiting firewall");

    puts("fw: main is joining the thread.");

    // sets not cancelled to false; the thread needs to close down
    NOT_CANCELLED = 0;

    // wait for the filter thread to terminate
    void * retval = NULL;
    int joinResult = pthread_join(tid_filter, &retval);
    if(joinResult != 0)
        printf("fw: main Error: unexpected joinResult: %d\n", joinResult);
    if ((void*)retval == PTHREAD_CANCELED)
        puts("fw: main confirmed that the thread was canceled.");

    puts("fw: main returning.");
    return EXIT_SUCCESS;
}
