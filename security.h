//-----------------------------------
// Dated: April 25,2005
// Created: Sam Tran and Tuan Nguyen.
// file name: security_packet.h
//-----------------------------------
#ifndef ns_security_packet_h
#define ns_security_packet_h

#include "agent.h"
#include "tclcl.h"
#include "packet.h"
#include "address.h"
#include "ip.h"

struct hdr_security_packet {
	char ret;
	double send_time;
 	double rcv_time;	// when security packet arrived at receiver
 	int seq;		// sequence number
	char data[128];
	unsigned int hashvalue; 

	// Header access methods
	static int offset_; // required by PacketHeaderManager
	inline static int& offset() { return offset_; }
	inline static hdr_security_packet* access(const Packet* p) {
		return (hdr_security_packet*) p->access(offset_);
	}
};

class Security_packetAgent : public Agent {
public:
	Security_packetAgent();
 	int seq;	
	int oneway; 	// enable seq number and one-way delay printouts
	virtual int command(int argc, const char*const* argv);
	virtual void recv(Packet*, Handler*);
	void encryption(char* out);
	void decryption(char* out);
	unsigned int hashing (char value[], unsigned int len);
};
#endif // ns_security_packet_h

