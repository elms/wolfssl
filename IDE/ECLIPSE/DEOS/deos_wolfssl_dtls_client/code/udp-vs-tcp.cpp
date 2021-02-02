#include <deos.h>
#include <videobuf.h>
#include <timeout.h>
#include <socketapi.h>
#include <lwip-socket.h>
#include <mem.h>
#include <string.h>

// *************************************************************************************************
// Description: Introduction to socket programming within Deos.
// This example demonstrates the basic use of the Deos Socket API Library, the Mailbox Transport
// Library and the Network Server Process by setting up a UDP and a TCP connection.  The Socket API
// Library relies on functions within the ANSI Library, and the Mailbox Transport Library requires a
// configuration file (mailbox-transport.config).  All of theses libraries and the config file must
// be loaded onto the target, and the C++ link options "Additional Options" within OpenArbor must
// include: -lsal -lansi -lmtl.
//
// The Deos Network Server is based on lwIP. Access to lwIP network stack socket capability and
// services is provided through the Socket Library API. Lack of Socket API support indicates
// unsupported lwIP service(s).  Please refer to the User Guide for the Deos LWIP Network Stack for
// details on which services are supported.
//
// To run this example, load your executable and mailbox-transport.config file onto the target,
// along with the libraries described above.  The main thread of the application creates two threads,
// one for the UDP connection and one for the TCP connection.  Once the application is running, you
// need to create the UDP and TCP clients, as follows:
//
// To create the UDP client, execute the UDP-echo.py script from a DESK command prompt.  This python
// script will prompt you to type anything.  If everything is loaded properly, you will see your
// data displayed on your target and echoed back to the DESK window.
//
// To create the TCP client, create a telnet session with the target. You will be prompted to enter
// some text.  If everything is loaded properly, the text you entered will be displayed on the
// target and echoed back to your telnet window.
//**************************************************************************************************

void goToSleep()
//**************************************************************************************************
// Function used to loop indefinitely when a failure occurs.  How you handle failure cases depends
// on your system requirements and design.  If you choose to delete the process with the failure,
// the video display destructor would run and any error messages displayed on the video display
// would be lost...therefore, it's better to loop forever.
//**************************************************************************************************
{
  while(1) waitUntilNextPeriod();
}


int setupTransport(clientConnectionHandleType &connectionHandle, char* connectionId)
//**************************************************************************************************
// Function used to set up the mailbox transport for a network connection.
// The steps for setting up the transport layer and establishing a connection with the Network
// Server are identical for UDP and TCP.  This example uses one MTL configuration file to configure
// both connections (UDP and TCP). Within Deos, you are only allowed one MTL config file per process.
// For details on the format and content of the config file refer to Chapter 3. Configuration File
// in the User Guide for the Deos Mailbox Transport Library.
//**************************************************************************************************
{
  int setupStatus, setupError;
  void * sendBuffer;
  uint32_t bufferSizeInBytes;
  VideoStream	VideoOutErr (14, 0, 4, 80);

  if ((setupStatus = socketTransportInitialize("mailbox-transport.config","transportConfigurationId",(uint32_t)waitIndefinitely,&setupError)) != transportSuccess)
    VideoOutErr << "socketTransportInitialize returned 0x" << setupStatus << ", error " << setupError << "\n";
  else if ((setupStatus = socketTransportClientInitialize((uint32_t)waitIndefinitely, &setupError)) != transportSuccess)
    VideoOutErr << "socketTransportClientInitialize returned 0x" << setupStatus << ", error " << setupError << "\n";
  else if ((setupStatus = socketTransportCreateConnection(connectionId, (uint32_t)waitIndefinitely, COMPATIBILITY_ID_2, &connectionHandle, &sendBuffer, &bufferSizeInBytes, &setupError)) != transportSuccess)
    VideoOutErr << "socketTransportCreateConnection returned 0x" << setupStatus << ", error " << setupError << "\n";
  else if ((setupStatus = socketTransportSetConnectionForThread(currentThreadHandle(), connectionHandle, (uint32_t)waitIndefinitely, &setupError)) != transportSuccess)
    VideoOutErr << "socketTransportSetConnectionForThread returned 0x" << setupStatus << ", error " << setupError << "\n";

  return setupStatus;
}

//#include <deos.h>
#include <printx.h>

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
//#include <wolfcrypt/test/test.h>
//#include <wolfcrypt/benchmark/benchmark.h>
#include <wolfssl/wolfcrypt/logging.h> /* to use WOLFSSL_MSG */
//#include <tls_wolfssl.h>

#include "ca_cert.h"
#define MAXLINE 128
#define SERV_PORT 11111

void UDPserver(uintData_t)
{
#if 0
//**************************************************************************************************
// Function (thread) to handle the UDP connection
//**************************************************************************************************
  clientConnectionHandleType UDPconnectionHandle;
  sockaddr_in socketAddr,clientAddr;
  int clientAddrSize = sizeof(clientAddr);
  int UDPsocket, bindStatus, receiveLength, transmitLength;
  char receiveBuffer[1528];
  void * sendBuffer;

  VideoStream VideoOutUDPtitle(3, 0, 1, 80);
  VideoStream VideoOutUDP(4, 0, 2, 80);

  // set up the mailbox transport
  if (setupTransport(UDPconnectionHandle, (char*)"connectionId1") != transportSuccess)
  {
    VideoOutUDP << "UDP transport set up failed \n";
    goToSleep();
  }

  // Create a UDP socket (SOCK_DGRAM); default set up is "blocking"
  UDPsocket = socket(AF_INET, SOCK_DGRAM, 0);
  if (UDPsocket == SOCKET_ERROR)
  {
    VideoOutUDP << "Error creating UDP socket \n";
    goToSleep();
  }

    // Bind the socket to port 1501
  socketAddr.sin_family = AF_INET;
  socketAddr.sin_port = htons(1501);
  socketAddr.sin_addr.s_addr = INADDR_ANY;
  if (bindStatus = bind(UDPsocket,(sockaddr*)&socketAddr,sizeof(socketAddr)) == SOCKET_ERROR)
  {
    VideoOutUDP << "Error binding UDP socket \n";
    goToSleep();
  }

  // Transport and socket were successfully set up
  VideoOutUDPtitle << "You must create the UDP client by executing udp-echo.py from DESK command prompt";

  while (1)
  {
    // Clear the receive buffer
    memset(receiveBuffer, 0, sizeof(receiveBuffer));

    // receive packet from the client
    receiveLength = recvfrom(UDPsocket, receiveBuffer, 1500, 0, (sockaddr*)&clientAddr, &clientAddrSize);

    if(receiveLength == SOCKET_ERROR)
    {
      VideoOutUDP << "UDP recvfrom() Error" <<  receiveLength << "\n";
    }
    else
    {
      VideoOutUDP.clear();
      VideoOutUDP << "Text message from the client: \n";
      VideoOutUDP << receiveBuffer << "\n";
    }

    // Send packet back to client
    socketAddr.sin_addr = clientAddr.sin_addr;
    transmitLength = sendto(UDPsocket, receiveBuffer, strlen(receiveBuffer), 0, (sockaddr*)&socketAddr, sizeof (socketAddr));
    if(transmitLength == SOCKET_ERROR)
    {
      VideoOutUDP << "UDP sendto() Error" <<  transmitLength << "\n";
    }
    waitUntilNextPeriod();
    // this thread loops forever, receiving and transmitting data to/from the UDP client
  } // end of while loop
#else
    clientConnectionHandleType UDPconnectionHandle;
    //int clientAddrSize = sizeof(clientAddr);
    //int UDPsocket, bindStatus, receiveLength, transmitLength;
    //char receiveBuffer[1528];
    //void * sendBuffer;

    VideoStream VideoOutUDPtitle(3, 0, 1, 80);
    VideoStream VideoOutUDP(4, 0, 2, 80);

    // set up the mailbox transport
    if (setupTransport(UDPconnectionHandle, (char*)"connectionId1") != transportSuccess)
    {
        VideoOutUDP << "UDP transport set up failed \n";
        goToSleep();
    }

    /* standard variables used in a dtls client*/
    int             n = 0;
    int             sockfd = 0;
    int             err1;
    int             readErr;
    struct          sockaddr_in servAddr;
    WOLFSSL*        ssl = 0;
    WOLFSSL_CTX*    ctx = 0;
    //char            cert_array[]  = "../certs/ca-cert.pem";
    //char*           certs = cert_array;
    char            sendLine[MAXLINE] = "test 1";
    char            recvLine[MAXLINE - 1];

    return;

    /* Initialize wolfSSL before assigning ctx */
    wolfSSL_Init();
    VideoOutUDP << "wolfSSL Init \n";

    //initPrintx("");
    //initPrintxP("");
  

    for (int i=0; i< 100; i++) {
      VideoOutUDP << "wait " << i << "\n";
      waitUntilNextPeriod();
    }
    //wolfSSL_Debugging_ON();
    VideoOutUDP << "wolfSSL debug\n";

    WOLFSSL_METHOD* method = wolfDTLSv1_2_client_method();
    if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
      VideoOutUDP << "wolfSSL_CTX_new error2.\n";
        //printf("wolfSSL_CTX_new error.\n");
        //return;// 1;
    }
    VideoOutUDP << "wolfSSL_CTX_new \n";

      
    /* Load certificates into ctx variable */
#if 0
    if (wolfSSL_CTX_load_verify_locations(ctx, certs, 0)
        != SSL_SUCCESS) {
        printf("Error loading %s, please check the file.\n", certs);
        return;// 1;
    }
#else
#if 0
    int ret = wolfSSL_CTX_load_verify_buffer(ctx,
                                                 ca_certs,
                                                 sizeof(ca_certs),
                                                 SSL_FILETYPE_PEM);
#else
    int ret = wolfSSL_CTX_load_verify_buffer_ex(ctx,
                                                 ca_certs,
                                                 sizeof(ca_certs),
                                                 SSL_FILETYPE_PEM,
												 0,
												 WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY);
#endif
    if(ret != SSL_SUCCESS) {
        //printf("Error loading certs\n");
    VideoOutUDP << "wolfSSL load certs failed\n";
        return;// 1;
    }
#endif
    VideoOutUDP << "wolfSSL_CTX_load_verify \n";

    /* Assign ssl variable */
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
    	VideoOutUDP << "unable to get ssl object";
        //printf("unable to get ssl object");
        return;// 1;
    }
    VideoOutUDP << "wolfSSL_new \n";

    /* servAddr setup */
    memset(&servAddr, 0, sizeof(servAddr));
    servAddr.sin_family = AF_INET;
    servAddr.sin_port = htons(SERV_PORT);
#if 0
    if (inet_pton(AF_INET, servAddr, &servAddr.sin_addr) < 1) {
        printf("Error and/or invalid IP address");
        return 1;
    }
#else
    uint8_t addr[4] = {192, 168, 86, 55};
    memcpy(&servAddr.sin_addr, addr, 4);
#endif


    wolfSSL_dtls_set_peer(ssl, &servAddr, sizeof(servAddr));

    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        printf("cannot create a socket.");
        return;// 1;
    }

    /* Set the file descriptor for ssl and connect with ssl variable */
    wolfSSL_set_fd(ssl, sockfd);
    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        err1 = wolfSSL_get_error(ssl, 0);
        printf("err = %d, %s\n", err1, wolfSSL_ERR_reason_error_string(err1));
        printf("SSL_connect failed");
        return;// 1;
    }
    VideoOutUDP << "wolfSSL_connect \n";

    /*****************************************************************************/
    /*                  Code for sending datagram to server                      */
    /* Loop until the user is finished */
    //if (fgets(sendLine, MAXLINE, stdin) != NULL)
    {

        /* Send sendLine to the server */
        if ( ( wolfSSL_write(ssl, sendLine, strlen(sendLine)))
             != strlen(sendLine)) {
            printf("SSL_write failed");
        }

        /* n is the # of bytes received */
        n = wolfSSL_read(ssl, recvLine, sizeof(recvLine)-1);

        if (n < 0) {
            readErr = wolfSSL_get_error(ssl, 0);
            if (readErr != SSL_ERROR_WANT_READ) {
                printf("wolfSSL_read failed");
            }
        }

        /* Add a terminating character to the generic server message */
        recvLine[n] = '\0';
        printf("rx: '%s'\n", recvLine);
        //fputs(recvLine, stdout);
    }
    /*                End code for sending datagram to server                    */
    /*****************************************************************************/

    /* Housekeeping */
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    //close(sockfd);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return;// 0;
#endif
} // end of UDPserver

void TCPserver(uintData_t)
//***************************************************************************************************
// Function (thread) to handle the TCP connection
// This thread is defined as a slack consumer in the pd (process developer) xml file.  For details
// on slack, refer to the Deos User's Guide, section "Slack Scheduling".
//***************************************************************************************************
{
  clientConnectionHandleType TCPconnectionHandle;
  sockaddr_in socketAddr;
  int socketAddrLen = sizeof(sockaddr);
  int TCPsocket, clientSocket, bindStatus;
  void * sendBuffer;
  #define MESSAGE_BUFFER_SIZE 80
  char messageBuffer[MESSAGE_BUFFER_SIZE];
  int numBytes, index;
  VideoStream VideoOutTCPtitle(8, 0, 1, 80);
  VideoStream VideoOutTCP(9, 0, 2, 80);

  // set up the mailbox transport
  if (setupTransport(TCPconnectionHandle, (char*)"connectionId2") != transportSuccess)
  {
    VideoOutTCP << "TCP transport set up failed \n";
    goToSleep();
  }

	// Create a TCP socket (SOCK_STREAM) to listen for connection requests; default set up is "blocking"
  TCPsocket = socket(AF_INET, SOCK_STREAM, 0);
  if (TCPsocket == SOCKET_ERROR)
  {
    VideoOutTCP << "Error creating TCP socket \n";
    goToSleep();
  }

  // Bind the socket to port 23
  socketAddr.sin_family = AF_INET;
  socketAddr.sin_port = htons(23);  // port number must be in network byte order
  socketAddr.sin_addr.s_addr = INADDR_ANY;
  if (bindStatus = bind(TCPsocket, (sockaddr *)&socketAddr, sizeof(sockaddr_in)) == SOCKET_ERROR)
  {
    VideoOutTCP << "Error binding TCP socket \n";
    goToSleep();
  }

  // Transport and socket were successfully set up
  VideoOutTCPtitle << "You must create the TCP client by starting a telnet session with the target";

  // Listen for a connection request from a client
  listen(TCPsocket, 1);

  char greeting1[] = "Greetings from the TCP server!\r\n\r\n";
  char greeting2[] = "Enter some text and it will be echoed back:\r\n\r\n";

  while (1)
  {
    // Accept a connection request from the client, and create a socket for communicating with the client.
    clientSocket = accept(TCPsocket, (sockaddr *)&socketAddr, &socketAddrLen);

    // Send the greeting to the client.
    send(clientSocket, greeting1, sizeof(greeting1), 0);
    send(clientSocket, greeting2, sizeof(greeting2), 0);

    while (1)
    {
      index = 0;
      // Receive characters from the TCP client until end-of-line is detected or the connection is closed.
      // The logic handles clients that send an entire line at once, or individual characters.
      // Messages containing control characters are ignored.
      do
      {
        numBytes = recv(clientSocket, messageBuffer+index, MESSAGE_BUFFER_SIZE-index, 0);
        if (((messageBuffer[index] >= 0x20) && (messageBuffer[index] <= 0x7E)) ||
            (messageBuffer[index] == '\r') || (messageBuffer[index] == '\n')) 
        {
          index += numBytes;
        }
      }
      while ((messageBuffer[index-2] != '\r') && (messageBuffer[index-1] != '\n') && (numBytes > 0));

      if (numBytes == 0) break;

      // Echo the received line of text back to the client
      messageBuffer[index]=0; // add null terminator to string
      send(clientSocket, messageBuffer, index, 0);

      // stream the message to the video display
      VideoOutTCP.clear();
      VideoOutTCP << "Text message from the client:\n";
      messageBuffer[index-2]=0; // "replace" the cr+lf with a null terminator
      VideoOutTCP << messageBuffer << "\n";
    } // loop indefinitely, receiving/transmitting data to/from the TCP client

    closesocket(clientSocket);
  }
} // end of TCPserver


int main(void)
//***************************************************************************************************
// The main() thread is responsible for creating the UDP and TCP threads...that's it.  So, once these
// two threads are created, we'll delete the main thread so that it's thread budget is returned to
// slack for other processes to use.
//***************************************************************************************************
{
  VideoStream VideoOutMain(0, 0, 3, 80);
  VideoOutMain << "UDP vs TCP Socket Example";

  // taken from hello-world-timer.cpp
  struct tm starttime = { 0, 30, 12, 1, 12, 2020-1900, 0, 0, 0 };
  // startdate: Dev 1 2020, 12:30:00
  struct timespec ts_date;
  ts_date.tv_sec  = mktime(&starttime);
  ts_date.tv_nsec = 0LL;
  int res1 = clock_settime(CLOCK_REALTIME, &ts_date);
  // this will only take effect, if time-control is set in the xml-file
  // if not, Jan 1 1970, 00:00:00 will be the date

  // Create the UDP and TCP server threads
  thread_handle_t UDPhandle, TCPhandle;
  threadStatus ts;
  ts = createThread("UDPserver", "UDPThreadTemplate", UDPserver, 0, &UDPhandle );
  if (ts != threadSuccess)
  {
    VideoOutMain << "Unable to create UDP server thread " << (uint32_t)ts << endl;
  }

  #if 0
  ts = createThread("TCPserver", "TCPThreadTemplate", TCPserver, 0, &TCPhandle );
  if (ts != threadSuccess)
  {
    VideoOutMain << "Unable to create TCP server thread " << (uint32_t)ts << endl;
  }
#endif
   // Let's go ahead and delete this thread
   deleteThread(currentThreadHandle());
}
