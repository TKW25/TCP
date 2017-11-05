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
#include "tcp.h"
#include "ip.h"

using namespace std;

unsigned int MSL_TIME_SECS = 120;

enum eState {
    CLOSED = 0,
    LISTEN = 1,
    SYN_RCVD = 2,
    ESTABLISHED = 3,
    SYN_SENT = 4,
    SEND_DATA = 5,
    CLOSE_WAIT = 6,
    FIN_WAIT1 = 7,
    FIN_WAIT2 = 8,
    CLOSING = 9,
    LAST_ACK = 10,
    TIME_WAIT = 11
};

enum HeaderType {
    SYN = 0,
    ACK = 1, 
    SYNACK = 3, 
    FIN = 4,
    FINACK = 5,
    RESET = 6
};

struct TCPState {
    eState state; //Current state, defined by enum eState
    //Following two unsigned ints use our sequence number
    unsigned int last_acked; 
    unsigned int last_sent;  
    Buffer SendBuffer;
    Buffer RecvBuffer;
    unsigned short rwnd;
    unsigned int last_recv; //Last received sequence number
    unsigned int win_size;
    time_t timer;
    std::ostream & Print(std::ostream &os) const { 
	os << "TCPState()\n" ; 
	os << state << endl << last_acked << endl << last_sent << endl;
	os << rwnd << endl << last_recv << endl << win_size << endl << timer << endl;
	return os;
    }
};

void MakeOutputPacket(Packet &p, ConnectionList<TCPState>::iterator cs, size_t size, bool t, HeaderType h);
void WrapMinetSend(const MinetHandle &mux, Packet p, bool corrupt, bool reorder, bool drop);


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
//    bool corrupt = false;
//    bool reorder = false;
//    bool drop = false;

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
			case LISTEN: //passive open, send SYN,ACK
			    //We only want to do something in this state if we receive a SYN
			    if(IS_SYN(flags)){
				cerr << "SYN Received, responding with SYN,ACK...\n";
				//In this state our connection is relatively incomplete so we need to update it
				cs->state.state = SYN_RCVD;
				cs->state.last_acked = cs->state.last_sent; //Set last_acked to our starting sequence number 
				cs->state.last_recv = seq;
				cs->bTmrActive = true;
				cs->timeout = Time() + 21; //I'm not certain if it matters what we add as long as we add soemthing
				cs->connection = c;
				//Our connection's state should be all setup correctly now
				//Make and send packet
				Packet out; MakeOutputPacket(out, cs, 0, false, SYNACK);
				cerr << out << endl;
				MinetSend(mux, out);
				cs->state.last_sent += 1; //Update our sequence number
			    }	
			    break;
			case SYN_RCVD: //Waiting to receive ACK of SYN
			    if(IS_ACK(flags)){
				cs->state.state = ESTABLISHED;
				cs->state.last_recv = seq;
				cs->state.last_acked = ack;
				cs->state.rwnd = ws;
				cs->bTmrActive = false; //Currently no unack'd packets
				//Send signal up to the socket
				SockRequestResponse write(WRITE, cs->connection, content, 0, EOK);
				MinetSend(sock, write);
				//Socket should eventually respond down to us with a STATUS
			    }
			    break; 
			case ESTABLISHED: //Handshake complete, receive data or FIN
			    if(IS_FIN(flags)){
				//Remote partner wishes to close connection
				cs->state.state = CLOSE_WAIT;
				cs->state.last_recv = seq;
				cs->state.rwnd = ws;
				cs->bTmrActive = true;
				cs->timeout = Time() + 21;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
				cs->state.last_sent += 1;
				//We need to inform the application remote partner has initiated close
				SockRequestResponse write(CLOSE, cs->connection, content, 0, EOK);
				MinetSend(sock, write);
			    }
			    else if(IS_SYN(flags)){
				//Our ACK from SYN_SEND was dropped, resend
				cs->state.last_recv = seq;
				cs->state.rwnd = ws;
				cs->bTmrActive = false;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
				//I'm assuming that we haven't sent any additional packets
				//So our sequence number should be the same as when we sent the
				//lost ACK
			    }
			    if(IS_ACK(flags)){
				//We might have received a FIN,ACK
				//Also could have simply received an ACK for data we've sent
				
				//We need to check if we've received a duplicate ack
				if(ack > cs->state.last_acked){
				   //ack is new, note we might have a cumulative ack
				   int cum = ack - cs->state.last_acked;
				   cs->state.SendBuffer.Erase(0, cum); //erase all acked packets from buffer
				   if(cs->state.SendBuffer.GetSize() == 0){
					//Nothing in send buffer, no need to timeout
					cs->bTmrActive = false;
				   }
				}
				else{
				   //Congestion control stuff would go here if we decide to implement it
				}
			    }
			    if(clen > 0){
				//We've received data to send up to the application
				cs->state.last_recv = seq + content.GetSize();
				cs->state.rwnd = ws;
				cs->state.RecvBuffer.AddBack(content);
				SockRequestResponse write(WRITE, cs->connection, cs->state.RecvBuffer, cs->state.RecvBuffer.GetSize(), EOK);
				//We'll clear RecvBuffer once socket sends us down a status telling us it's read it
				//But regardless we ACK
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
				cs->state.last_sent += 1;
			    }
			    break;
			case SYN_SENT: //Waiting to receive SYN,ACK or SYN
			    if(IS_SYN(flags) && IS_ACK(flags)){
				//Received SYN,ACK respond with ACK and move to ESTABLISHED
				cs->state.state = ESTABLISHED;
				cs->state.last_acked = ack;
				cs->state.last_recv = seq;
				cs->state.rwnd = ws;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
				cs->state.last_sent += 1;
			    }
			    else if(IS_SYN(flags)){
				//Receive SYN, move to SYN_RECV
				cs->state.state = SYN_RCVD;
				cs->state.last_recv = seq;
				cs->state.rwnd = ws;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
				cs->state.last_sent += 1;
			    }
			    break;
			case SEND_DATA: break;  //Do nothing, in process of sending data. This state might not be necessary
			case CLOSE_WAIT: break; //Do nothing, waiting for socket to send down CLOSE
			case FIN_WAIT1: //Sent FIN waiting for ACK or FIN
			    if(IS_ACK(flags))
				cs->state.state = FIN_WAIT2; 
			    if(!IS_FIN(flags))
			        break;
			    //Fallthrough, we've received a FINACK
			case FIN_WAIT2: //Waiting for FIN after sending a FIN and receiving an ACK
			    if(IS_FIN(flags)){
				cs->state.state = TIME_WAIT;
				cs->state.last_recv = seq;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				//We need to setup a timeout in case this ACK gets lost so our partner
				//can close elegantly
				cs->bTmrActive = true;
				cs->timeout = Time() + (2*MSL_TIME_SECS);
				MinetSend(mux, out);
				//No need to update our sequence number since at this point
				//the only packets we should be sending is resending this packet
				//if it gets lost.  At least I think...
			    }
			    break;
			case CLOSING: break; //Received FIN while waiting for ACK of FIN
			case LAST_ACK: //Received FIN, sent ACK and FIN, now waiting for final ACK
			    if(IS_ACK(flags)){
				//Got our final ack, close the connection
				cs->state.state = CLOSED;
				clist.erase(cs);
			    }
			    break;
			case TIME_WAIT: //Received FIN sent  ACK, wait for timeout (2MSL) in case ACK gets lost
			    if(IS_FIN(flags)){
				//resend ACK and reset the timer
				cs->state.last_recv = seq;
				cs->timeout = Time() + (2*MSL_TIME_SECS);
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
			    }
			    break;
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

void MakeOutputPacket(Packet &p, ConnectionList<TCPState>::iterator cs, size_t size, bool t, HeaderType h){
    //We'll be doing this alot so it's more convenient to have this in a function
    //Even if it makes the code a little more complex here
    IPHeader iph;
    TCPHeader tcph;
    size += IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH;
    //Build IP header
    iph.SetProtocol(IP_PROTO_TCP);
    iph.SetSourceIP(cs->connection.src);
    iph.SetDestIP(cs->connection.dest);
    iph.SetTotalLength(size);
    cerr << iph << endl;
    //Push it on packet
    p.PushFrontHeader(iph);
    //Build TCP Header
    tcph.SetHeaderLen(5, p);
    tcph.SetSourcePort(cs->connection.srcport, p);
    tcph.SetDestPort(cs->connection.destport, p);
    tcph.SetAckNum(cs->state.last_recv + 1, p);
    tcph.SetWinSize(cs->state.win_size, p);
    tcph.SetUrgentPtr(0, p);
    //Check if we're retransmitting
    if(t){
	//Since ack is the next expected packet
	//we want to send the last ack number received
	tcph.SetSeqNum(cs->state.last_acked, p); 
    }
    else{
	//Otherwise just set it to last_sent
	//Assumes we've properly updated last_sent before calling make packet
	tcph.SetSeqNum(cs->state.last_sent, p);
    }
    //Get appropriate flags
    unsigned char flags;
    switch(h){
	case SYN: SET_SYN(flags); break;
	case ACK: SET_ACK(flags); break;
	case SYNACK: SET_SYN(flags); SET_ACK(flags); break;
	case FIN: SET_FIN(flags); break;
	case FINACK: SET_FIN(flags); SET_ACK(flags); break;
	case RESET: SET_RST(flags); break;
	default: cerr << "Something is broke\n"; break;
    }
    tcph.SetFlags(flags, p);
    tcph.RecomputeChecksum(p);
    //Finished building TCP header
    cerr << tcph << endl;
    if(!tcph.IsCorrectChecksum(p)){
	cerr << "Checksum failed in building packet, something is seriously wrong\n";
    }
    //Put it in the packet
    p.PushBackHeader(tcph);
} 

void WrapMinetSend(const MinetHandle &mux, Packet p, bool corrupt, bool reorder, bool drop){
    //This should be used for error testing but we're kinda short on time so probably won't be
    MinetSend(mux, p);
}
