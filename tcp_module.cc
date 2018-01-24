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
unsigned int TCP_MAXIMUM_SEGMENT_SIZE = 536;
unsigned int TCP_BUFFER_SIZE = 536 * 100;

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
    RESET = 6,
    NOFLAG = 999
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

void MakeOutputPacket(Packet &p, ConnectionList<TCPState>::iterator cs, int size, bool t, HeaderType h);
bool SendOutputData(const MinetHandle &mux, ConnectionList<TCPState>::iterator cs, Buffer d, bool t);

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
		checksumok = tcph.IsCorrectChecksum(p);
		Connection c;
		iph.GetDestIP(c.src);
		iph.GetSourceIP(c.dest);
		iph.GetProtocol(c.protocol);
		tcph.GetDestPort(c.srcport);
		tcph.GetSourcePort(c.destport);
		//End copied UDP boilerplate
		cerr << tcph << endl;
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
				cerr << "In LISTEN... SYN Received, responding with SYN,ACK...\n";
				//In this state our connection is relatively incomplete so we need to update it
				cs->state.state = SYN_RCVD;
				cs->state.last_acked = cs->state.last_sent; //Set last_acked to our starting sequence number 
				cs->state.last_recv = seq;
				cs->bTmrActive = true;
				cs->state.win_size = TCP_BUFFER_SIZE;
				cs->state.rwnd = ws;
				cs->timeout = Time() + 1; //Short timeout since minet will drop anyway
				cs->connection = c;
				//Our connection's state should be all setup correctly now
				//Make and send packet
				Packet out; MakeOutputPacket(out, cs, 0, false, SYNACK);
				MinetSend(mux, out);
				cs->state.last_sent += 1; //Update our sequence number
			    }	
			    break;
			case SYN_RCVD: //Waiting to receive ACK of SYN
			    if(IS_ACK(flags)){
				cerr << "In SYN_RCVD... ACK received...\n";
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
			    cerr << "In ESTABLISHED\n";
			    if(IS_FIN(flags)){
				//Remote partner wishes to close connection
				cerr << "FIN received\n";
				cs->state.state = CLOSE_WAIT;
				cs->state.last_recv = seq;
				cs->state.rwnd = ws;
				cs->bTmrActive = true;
				cs->timeout = Time() + 8;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
				//We need to inform the application remote partner has initiated close
				SockRequestResponse write;
				write.type = WRITE;
				write.connection = cs->connection;
				write.bytes = 0;
				MinetSend(sock, write);
			    }
			    else if(IS_SYN(flags)){
				//Our ACK from SYN_SEND was dropped, resend
				cerr << "SYN received\n";
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
				cerr << "ACK received\n";
				//We need to check if we've received a duplicate ack
				if(ack > cs->state.last_acked){
				   //ack is new, note we might have a cumulative ack
				   cerr << "is it\n";
				   int cum = ack - cs->state.last_acked;
				   cs->state.SendBuffer.Erase(0, cum); //erase all acked packets from buffer
				   if(cs->state.SendBuffer.GetSize() == 0){
					//Nothing in send buffer, no need to timeout
					cs->bTmrActive = false;
				   }
				   cs->state.last_acked = ack;
				}
				else{
				   //Congestion control stuff would go here if we decide to implement it
				}
			    }
			    if(cs->state.state == CLOSE_WAIT)
				break;
			    if(clen > 0){
				//We've received data to send up to the application
				cerr << "Received content\n";
				cerr << content << endl;

				//Find number of NULL (padding) bytes in content
				int pad = 1;
				for(unsigned int i = 0; i < content.GetSize(); i++){
				    cerr << content[i];
				    if(content[i] == 0)
					pad++;
				}
				pad = content.GetSize() - pad;

				cs->state.last_recv = seq + pad;
				cs->state.rwnd = ws;
				cs->state.RecvBuffer.AddBack(content);
				SockRequestResponse write(WRITE, cs->connection, cs->state.RecvBuffer, cs->state.RecvBuffer.GetSize(), EOK);
				//We'll clear RecvBuffer once socket sends us down a status telling us it's read it
				//But regardless we ACK
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(sock, write);
				MinetSend(mux, out);
			    }
			    break;
			case SYN_SENT: //Waiting to receive SYN,ACK or SYN
			    cerr << "In SYN_SENT\n";
			    if(IS_SYN(flags) && IS_ACK(flags)){
				//Received SYN,ACK respond with ACK and move to ESTABLISHED
				cerr << "Received SYNACK\n";
				cs->state.state = ESTABLISHED;
				cs->bTmrActive = false;
				cs->state.last_acked = ack;
				cs->state.last_recv = seq;
				cs->state.rwnd = ws;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
				SockRequestResponse write;
				write.type = WRITE; 
				write.connection = cs->connection;
				write.bytes = 0;
				write.error = EOK;
				MinetSend(sock, write);
			    }
			    else if(IS_SYN(flags)){
				//Receive SYN, move to SYN_RECV
				cerr << "received SYN\n";
				cs->state.state = SYN_RCVD;
				cs->state.last_recv = seq;
				cs->state.rwnd = ws;
				cs->bTmrActive = true;
				cs->timeout = Time() + 8;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
				cs->state.last_sent += 1;
			    }
			    else{
				cs->timeout = Time() + 8;
			    }
			    break;
			case SEND_DATA: break;  //Do nothing, in process of sending data. 
			case CLOSE_WAIT: break; //Do nothing, waiting for socket to send down CLOSE.
			case FIN_WAIT1: //Sent FIN waiting for ACK or FIN
			    cerr << "In FIN_WAIT1\n";
			    if(IS_ACK(flags))
				cs->state.state = FIN_WAIT2; 
			    else if(IS_FIN(flags)){
				cs->state.state = CLOSING;
				cs->state.last_recv = seq;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				break;
			    }
			    if(!IS_FIN(flags))
			        break; 
			    //Fallthrough, we've received a FINACK
			case FIN_WAIT2: //Waiting for FIN after sending a FIN and receiving an ACK
			    if(IS_FIN(flags)){
				cerr << "In FIN_WAIT2\n";
				cs->state.state = TIME_WAIT;
				cs->state.last_recv = seq;
				cs->state.last_sent += 1;
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				//We need to setup a timeout in case this ACK gets lost so our partner
				//can close elegantly
				cs->bTmrActive = true;
				cs->timeout = Time() + (2*MSL_TIME_SECS);
				MinetSend(mux, out);
				//No need to update our sequence number since at this point
				//the only packets we should be sending is resending this packet
				//if it gets lost.
			    }
			    break;
			case CLOSING: 
			    //Received FIN while waiting for ACK of FIN
			    cerr << "In CLOSING\n";
			    if(IS_ACK){
				cs->state.state = TIME_WAIT;
				cs->state.last_recv = seq;
			    }
			    break;
			case LAST_ACK: //Received FIN, sent ACK and FIN, now waiting for final ACK
			    if(IS_ACK(flags)){
				//Got our final ack, close the connection
				cerr << "In LAST_ACK, closing connection\n";
				cs->state.state = CLOSED;
				clist.erase(cs);
			    }
			    break;
			case TIME_WAIT: //Received FIN sent  ACK, wait for timeout (2MSL) in case ACK gets lost
			    if(IS_FIN(flags)){
				//resend ACK and reset the timer
				cerr << "IN TIME_WAIT, resending";
				cs->state.last_recv = seq;
				cs->timeout = Time() + (2*MSL_TIME_SECS);
				Packet out; MakeOutputPacket(out, cs, 0, false, ACK);
				MinetSend(mux, out);
			    }
			    break;
		    }
		    cerr << "Nothing is happening\n";
		}
		else{
		    //Packet corrupted print error monitor and do nothing
		    cerr << "ERROR! Corrupted Packet\n";
		    MinetSendToMonitor(MinetMonitoringEvent("ERROR! Corrupted Packet\n"));
		}
	    }

	    if (event.handle == sock) {
		// socket request or response has arrived
		cerr << "Socket event detected\n";
		SockRequestResponse req;
		MinetReceive(sock, req);
		ConnectionList<TCPState>::iterator cs = clist.FindMatching(req.connection);
		if(cs == clist.end()){
		    //Connection doesn't exist
		    cerr << "Connection doesn't exist, creating\n";
		    switch(req.type){
			case CONNECT: {
			    //Active open
			    //Create a new TCPState
			    cerr << "Active open...\n";
			    TCPState state; 
			    state.state = SYN_SENT;
			    state.last_recv = -1;
			    state.rwnd = 0;
			    srand(Time());
			    state.last_sent = (unsigned int) rand() % 1000000;
			    state.last_acked = state.last_sent;
			    state.win_size = TCP_BUFFER_SIZE;
			    //Create a Connection State Mapping to add to clist
			    ConnectionToStateMapping<TCPState> CTSM(req.connection, Time()+2, state, true);
			    //We set a short timer since we want to timeout quickly since Minet is
			    //going to throw away our first packet
			    clist.push_back(CTSM); //add connection on clist
			    //Make output packet
			    cs = clist.FindMatching(req.connection);
			    cs->bTmrActive = true;
			    cs->timeout = Time() + 2;
			    Packet out; MakeOutputPacket(out, cs, 0, false, SYN);
			    MinetSend(mux, out);
			    //Now that we've successfully created our packet we need to let the application know
			    SockRequestResponse reply;
			    reply.type = STATUS;
			    reply.connection = req.connection;
			    reply.error = EOK;
			    MinetSend(sock, reply);
			    cerr << "Replying: " << reply << endl;
			    break; }
			case ACCEPT: {
			    //Passive open
			    //Set up TCP state
			    cerr << "Passive open..\n";
			    TCPState state;
			    state.state = LISTEN;
			    state.last_recv = 0;
			    state.rwnd = 0;
			    srand(Time());
			    state.last_acked = rand();
			    state.last_sent = state.last_acked;
			    //Create Connection to State Mapping
			    ConnectionToStateMapping<TCPState> CTSM(req.connection, Time(), state, false);
			    clist.push_back(CTSM);
			    //Message socket
			    SockRequestResponse reply;
			    reply.type = STATUS;
			    reply.error = EOK;
			    MinetSend(sock, reply);
			    cerr << "Replying: " << reply << endl;
			    break; }
			case WRITE: {
			    //Can't write on a connection which doesn't exist
			    cerr << "Error trying to write...\n";
			    SockRequestResponse reply;
			    reply.type = STATUS;
			    reply.error = ENOMATCH;
			    MinetSend(sock, reply);
			    cerr << "Replying: " << reply << endl;			    
			    break; }
			case FORWARD: {
			    //TCP will just return a status here
			    cerr << "Forwarding...\n";
			    SockRequestResponse reply;
			    reply.type = STATUS;
			    reply.error = EOK;
			    MinetSend(sock, reply);
			    cerr << "Replying: " << reply << endl;
			    break; }
			case CLOSE: {
			    //Can't close a connection which doesn't exist
			    cerr << "Errror trying to close\n";
			    SockRequestResponse reply;
			    reply.type = STATUS;
			    reply.connection = req.connection;
			    reply.error = ENOMATCH;
			    MinetSend(sock, reply);
			    cerr << "Replying: " << reply << endl;
			    break; }
			case STATUS: {
			    //This shouldn't happen
			    cerr << "ERror status\n";
			    SockRequestResponse reply;
			    reply.type = STATUS;
			    reply.error = ENOMATCH;
			    MinetSend(sock, reply);
			    cerr << "Replying: " << reply << endl;
			    break; }
		    }
		}
		else{
		    //Connection exists
		    cerr << "Connection exists...\n";
		    switch(req.type){
			case CONNECT:
			    //already connected
			    break;
			case ACCEPT:
			    //already connected
			    break;
			case WRITE: {
			    //Send buffer contents to remote partner
			    if(cs->state.state == ESTABLISHED){
				if(cs->state.SendBuffer.GetSize() + req.data.GetSize() > TCP_BUFFER_SIZE){
				    //Not enough space in Buffer, inform application that we're dropping it
				    cerr << "Buffer can't fit data\n";
				    SockRequestResponse reply;
				    reply.type = STATUS;
				    reply.error = EBUF_SPACE;
				    MinetSend(sock, reply);
				    cerr << "Replying: " << reply << endl;
				}
				else{
				    //Add new data to send buffer
				    cerr << "Sending out data...";
				    int size = req.data.GetSize();
				    bool success = SendOutputData(mux, cs, req.data, false);
				    cs->bTmrActive = true;
				    cs->timeout = Time() + 8;
				    if(success){
					SockRequestResponse reply;
					reply.type = STATUS;
					reply.error = EOK;
					reply.connection = req.connection;
					reply.bytes = size;
					MinetSend(sock, reply);
					cerr << "Repltying: " << reply << endl;
				    }
				    else{
					SockRequestResponse reply;
					reply.type = STATUS;
					reply.error = EUNKNOWN;
					MinetSend(sock, reply);
					cerr << "Replying: " << reply << endl;
				    }
				}
			    }
			    else{
				SockRequestResponse reply;
				reply.type = STATUS;
				reply.error = EINVALID_OP;
				MinetSend(sock, reply);
				cerr << "Replying; " << reply << endl;
			    }
			    break; }
			case FORWARD: {
			    SockRequestResponse reply;
			    reply.type = STATUS;
			    reply.error = EOK;
			    MinetSend(sock, reply);
			    cerr << "Forwarding...\nReplying: " << reply << endl;
			    break; }
			case CLOSE: {
			    //Close the connection
			    cerr << "Closing connection\n";
			    eState s = cs->state.state;
			    if(s == ESTABLISHED || s == SYN_RCVD || s == CLOSE_WAIT){
				//Valid state to receive CLOSE
				cerr << "Valid clsoe\n";
				if(s == CLOSE_WAIT)
				    cs->state.state = LAST_ACK;
				else
				    cs->state.state = FIN_WAIT1;
				cs->bTmrActive = true;
				cs->timeout = Time() + 8;
				//Send packet
				Packet out; MakeOutputPacket(out, cs, 0, false, FINACK);
				MinetSend(mux, out);
				//Inform socket
				SockRequestResponse reply;
				reply.type = STATUS;
				reply.error = EOK;
				reply.connection = req.connection;
				MinetSend(sock, reply);
				cerr << "Replying: " << reply << endl;
			    }
			    break; }
			case STATUS: {
			    //Resend unaccepted bytes to sock
			    cerr << "Resending data to application\n";
			    cs->state.RecvBuffer.Erase(0, req.bytes); //Delete accepted bytes
			    if(cs->state.RecvBuffer.GetSize() != 0){
			        //Resend unaccepted ones
			        SockRequestResponse write(WRITE, cs->connection, cs->state.RecvBuffer, cs->state.RecvBuffer.GetSize(), EOK);
			        MinetSend(sock, write);
			        cerr << "Replying: " << write << endl;
			        break; 
			    }
			    else
				cerr << "Everything accepted!\n";}
		    }
		}
	    }
	}

	if (event.eventtype == MinetEvent::Timeout) {
	    // timeout ! probably need to resend some packets
	    ConnectionList<TCPState>::iterator cs = clist.FindEarliest();
	    if(cs != clist.end()){ //Make sure our list isn't empty
		if(Time() > cs->timeout){ //See if it's timed out
		    //There are a few potential states where we can get a timeout
		    //SYN_SENT we need to resend our SYN
		    //SYN_RCVD we need to resend our SYNACK
		    //Both FIN_WAIT1 and LAST_ACK we need to resnd FIN
		    //TIME_WAIT we need to close the connection
		    //ESTABLISHED we might need to resend our SendBuffer
		    cerr << "TIMEOUT in: " << cs->state.state << endl;
		    switch(cs->state.state){
			case SYN_RCVD: {
			    Packet out; MakeOutputPacket(out, cs, 0, true, SYNACK);
			    MinetSend(mux, out);
		 	    break; }
			case ESTABLISHED: {
			    SendOutputData(mux, cs, cs->state.SendBuffer, true);
			    break; }
			case SYN_SENT: {
			    Packet out; MakeOutputPacket(out, cs, 0, true, SYN);
			    MinetSend(mux, out);
			    cs->state.last_sent += 1;
			    break; }
			case FIN_WAIT1: {
			    Packet out; MakeOutputPacket(out, cs, 0, true, FIN);
			    MinetSend(mux, out);
			    break; }
			case LAST_ACK: {
			    Packet out; MakeOutputPacket(out, cs, 0, true, FIN);
			    MinetSend(mux, out);
			    break; }
			case TIME_WAIT: {
			    cs->state.state = CLOSED;
			    clist.erase(cs);
			    break; }
			case CLOSED: break;
			case LISTEN: break;
			case SEND_DATA: break;
			case CLOSE_WAIT: break;
			case FIN_WAIT2: break;
			case CLOSING:{
			    Packet out; MakeOutputPacket(out, cs, 0, true, ACK);
			    MinetSend(mux, out);
			    break; }
			default: break;
		    }
		}
	    }
	}

    }

    MinetDeinit();

    return 0;
}

bool SendOutputData(const MinetHandle &mux, ConnectionList<TCPState>::iterator cs, Buffer d, bool t){
    //Send our sendbuffer + d to remote host
    cerr << "Preparing to send data\n";
    size_t left;
    size_t off = 0;
    if(t){
	left = cs->state.SendBuffer.GetSize();
    }
    else{
	off = cs->state.SendBuffer.GetSize();
	left = d.GetSize();
	cs->state.SendBuffer.AddBack(d);
    }
    bool first = true;
    unsigned int to_send;
    int size;
    Buffer send;
    Packet out;
    while(left != 0){
	to_send = min(left, TCP_MAXIMUM_SEGMENT_SIZE);
        char buff[to_send + 1];
	size = cs->state.SendBuffer.GetData(buff, to_send, off);
	buff[to_send + 1] = '\0';
	send.SetData(buff, size, 0);
	out = send.Extract(0, size);
	left -= to_send;
	off += size;
	if(first) {
	    MakeOutputPacket(out, cs, size, t, NOFLAG);
	    first = false;
	}
	else
	    MakeOutputPacket(out, cs, size, false, NOFLAG);
	MinetSend(mux, out);
	cs->state.last_sent += to_send;
    }
    cerr << "Finished sending data...\n";
    if(left == 0)
	return true;
    else
	return false;
}
void MakeOutputPacket(Packet &p, ConnectionList<TCPState>::iterator cs, int size, bool t, HeaderType h){
    //Code is more complex here for the sake of reuse
    cerr << "Creating packet to send...\n";
    IPHeader iph;
    TCPHeader tcph;
    size += IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH;
    //Build IP header
    iph.SetProtocol(IP_PROTO_TCP);
    iph.SetSourceIP(cs->connection.src);
    iph.SetDestIP(cs->connection.dest);
    iph.SetTotalLength(size);
    

    //Push it on packet
    p.PushFrontHeader(iph);
    //Build TCP Header
    tcph.SetSourcePort(cs->connection.srcport, p);
    tcph.SetDestPort(cs->connection.destport, p);
    tcph.SetHeaderLen(5, p);
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
    unsigned char flags = 0000;
    switch(h){
	case SYN: SET_SYN(flags); break;
	case ACK: SET_ACK(flags); break;
	case SYNACK: SET_SYN(flags); SET_ACK(flags); break;
	case FIN: SET_FIN(flags); break;
	case FINACK: SET_FIN(flags); SET_ACK(flags); break;
	case RESET: SET_RST(flags); break;
	case NOFLAG: SET_ACK(flags); SET_PSH(flags);
	default: cerr << "Sending data...\n";  break;
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
