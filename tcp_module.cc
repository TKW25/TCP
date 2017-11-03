// You will build this in project part B - this is merely a
// stub that does nothing but integrate into the stack

// For project parts A and B, an appropriate binary will be 
// copied over as part of the build process



#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"

using namespace std;

enum eState {
    CLOSED = 0,
    LISTEN = 1,
    SYN_RCVD = 2,
    SYN_SENT = 3,
    ESTABLISHED = 4,
    SEND_DATA = 5,
    CLOSE_WAIT = 6,
    FIN_WAIT1 = 7,
    CLOSING = 8,
    LAST_ACK = 9,
    FIN_WAIT2 = 10,
    TIME_WAIT = 11
};

struct TCPState {
    eState state; //Current state, defined by enum eState
    unsigned int last_acked; 
    unsigned int last_sent; 
    Buffer SendBuffer;
    Buffer RecvBuffer;
    unsigned short rwnd;
    unsigned int last_recv;
    unsigned int win_size;
    time_t timer;
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()\n" ; 
	os << state << endl << last_acked << endl << last_sent << endl;
	os << rwnd << endl << last_recv << endl << win_size << endl << timer << endl;
	return os;
    }
};


int main(int argc, char * argv[]) {
    MinetHandle mux;
    MinetHandle sock;
    
    ConnectionList<TCPState> clist;

    MinetInit(MINET_TCP_MODULE);

    mux = MinetIsModuleInConfig(MINET_IP_MUX) ?  
	MinetConnect(MINET_IP_MUX) : 
	MINET_NOHANDLE;
    
    sock = MinetIsModuleInConfig(MINET_SOCK_MODULE) ? 
	MinetAccept(MINET_SOCK_MODULE) : 
	MINET_NOHANDLE;

    if ( (mux == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_IP_MUX)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't connect to ip_mux"));

	return -1;
    }

    if ( (sock == MINET_NOHANDLE) && 
	 (MinetIsModuleInConfig(MINET_SOCK_MODULE)) ) {

	MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock_module"));

	return -1;
    }
    
    cerr << "tcp_module STUB VERSION handling tcp traffic.......\n";

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module STUB VERSION handling tcp traffic........"));

    MinetEvent event;
    double timeout = 1;
    //Debugging bools, set to true to test if we handle errors correctly
    bool corrupt = false;
    bool reorder = false;
    bool drop = false;

    while (MinetGetNextEvent(event, timeout) == 0) {
	if ((event.eventtype == MinetEvent::Dataflow) && 
	    (event.direction == MinetEvent::IN)) {
	
	    if (event.handle == mux) {
		// ip packet has arrived
		cerr << "IP Packet received\n";
		Packet p;
		bool checksumok;
		MinetReceive(mux, p);
		unsigned short len = TCPHeader::EstimateTCPHeaderLength(p);
		p.ExtractHeaderFromPayload<TCPHeader>(len);
		TCPHeader tcph = p.FindHeader(Headers::TCPHeader);
		IPHeader iph = p.FindHeader(Headers::IPHeader);
		cerr << iph << "~~~~~~~~~~~~~~\n";
		cerr << tcph << "~~~~~~~~~~~~~~~\n";
		checksumok = tcph.IsCorrectChecksum(p);
		Connection c;
		iph.GetDestIP(c.src);
		iph.GetSourceIP(c.dest);
		iph.GetProtocol(c.protocol);
		tcph.GetDestPort(c.srcport);
		tcph.GetSourcePort(c.destport);
		//End copied UDP boilerplate

		//Get tcp and ip header information
		unsigned char flags; //URG, ACK, PSH, RST, SYN, FIN
		tcph.GetFlags(flags);
		unsigned int ack;
		tcph.GetAckNum(ack);
		unsigned int seq;
		tcph.GetSeqNum(seq);
		unsigned short ws;
		tcph.GetWinSize(ws);
		unsigned char thlen;
		tcph.GetHeaderLen(thlen);
		unsigned short clen;
		iph.GetTotalLength(clen);
		unsigned char ihlen;
		iph.GetHeaderLength(ihlen);
		//We need to get the contents length which is the total length - headers length
		clen -= (thlen * 4) - (ihlen * 4);
		//Get packet content
		Buffer content = p.GetPayload().ExtractFront(clen);
		//Get Connection's State
		ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);
		//All relevant TCP information collected

		//Error check and handle Packet
		if(checksumok){
		    //Handle packet
		    switch(cs->state.state){ 
			case CLOSED: break; //Default case do nothing not listening
			case LISTEN: break; //Passive open, send SYN,ACK
			case SYN_RCVD: break; //Waiting to receive ACK of SYN
			case SYN_SENT: break; //Waiting to receive SYN,ACK or SYN
			case ESTABLISHED: break; //Handshake complete, receive DATA or FIN
			case SEND_DATA: break;  //Do nothing, in process of sending data. This state might not be necessary
			case CLOSE_WAIT: break; //Do nothing, waiting for socket to send down CLOSE
			case FIN_WAIT1: break; //Sent FIN waiting for ACK or FIN
			case CLOSING: break; //Received FIN while waiting for ACK of FIN
			case LAST_ACK: break; //Received FIN, sent ACK and FIN, now waiting for final ACK
			case FIN_WAIT2: break; //Waiting for FIN after sending a FIN and receiving an ACK
			case TIME_WAIT: break; //Received FIN sent  ACK, wait for timeout (2MSL) in case ACK gets lost
		    }
		}
		else{
		    //Packet corrupted print error monitor and do nothing
		    cerr << "ERROR! Corrupted Packet\n";
		    MinetSendToMonitor(MinetMonitoringEvent("ERROR! Corrupted Packet\n"));
		}
	    }

	    if (event.handle == sock) {
		// socket request or response has arrived
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	}

    }

    MinetDeinit();

    return 0;
}
