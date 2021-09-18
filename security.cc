// Created: Sam Tran and Tuan Nguyen.
// file name: security_packet.cc
//-----------------------------------
#include "security.h"
#include "string.h"

int hdr_security_packet::offset_;
static class Security_packetHeaderClass : public PacketHeaderClass {
public:
	Security_packetHeaderClass() : PacketHeaderClass("PacketHeader/Security_packet",sizeof(hdr_security_packet)) {
		bind_offset(&hdr_security_packet::offset_);
	}
} class_security_packethdr;


static class Security_packetClass : public TclClass {
public:
	Security_packetClass() : TclClass("Agent/Security_packet") {}
	TclObject* create(int, const char*const*) {
		return (new Security_packetAgent());
	}
} class_security_packet;


Security_packetAgent::Security_packetAgent() : Agent(PT_SECURITY_PACKET), seq(0), oneway(0)
{
	bind("packetSize_", &size_);
}

int Security_packetAgent::command(int argc, const char*const* argv)
{

if (argc ==3) {

    if (strcmp(argv[1], "send") == 0) {
      // Create a new packet
      Packet* pkt = allocpkt();
      // Access the security packet header for the new packet:
      hdr_security_packet* hdr = hdr_security_packet::access(pkt);
      // Set the 'ret' field to 0, so the receiving node
      // knows that it has to generate an acknowledge packet
      hdr->ret = 0;
      hdr->seq = seq++;
      // Store the current time in the 'send_time' field
      hdr->send_time = Scheduler::instance().clock();
      // copy date to be sent to header
      strcpy(hdr->data, argv[2]);
      //----------------hashing------------------------
      hdr->hashvalue = hashing(hdr->data,(unsigned int)strlen(hdr->data));
      printf("Message sent %s with hashing %d\n",hdr->data,hdr->hashvalue);
      // ---------- encrypt the data ---------------
      encryption(hdr->data);
      //-----------------------------------
      // Send the packet
      send(pkt, 0);
      // return TCL_OK, so the calling function knows that
      // the command has been processed
      return (TCL_OK);    
    }    
    else if (strcmp(argv[1], "start-WL-brdcast") == 0) {
      Packet* pkt = allocpkt();
      
      hdr_ip* iph = HDR_IP(pkt);
      hdr_security_packet* ph = hdr_security_packet::access(pkt);
      strcpy(ph->data, "test");
      
      iph->daddr() = IP_BROADCAST;
      iph->dport() = iph->sport();
      ph->ret = 0;
      send(pkt, (Handler*) 0);
      return (TCL_OK);
    }

    else if (strcmp(argv[1], "oneway") == 0) {
      oneway=1;
      return (TCL_OK);
    }
  }
  
  // If the command hasn't been processed by SecurityAgent()::command,
  // call the command() function for the base class
  return (Agent::command(argc, argv));
}
// -- CESAR encryption function ----------
void Security_packetAgent::encryption(char out[])
{ 
	int key =3;
	int i=0;
		for (i=0;i<strlen(out);i++)
	{
		out[i]=(out[i]+key)%128;
	}
}
// ---- CESAR decryption  ------------------
void Security_packetAgent::decryption(char out[])
{ 
	int key =3;
	int i=0;
		for (i=0;i<strlen(out);i++)
	{
		out[i]=(out[i]-key)%128;
	}
	
}
//---------------hashing fucntion-------------
unsigned int Security_packetAgent::hashing(char value[], unsigned int len)
{
   char *word = value;
   unsigned int ret = 0; 
   unsigned int i;  
   for(i=0; i < len; i++)
   {
      int mod = i % 32;
      ret ^=(unsigned int) (word[i]) << mod;
      ret ^=(unsigned int) (word[i]) >> (32 - mod);
   }
   return ret;
}
//-------------------------------
void Security_packetAgent::recv(Packet* pkt, Handler*)
{
  // Access the IP header for the received packet:
  hdr_ip* hdrip = hdr_ip::access(pkt);
  
  // Access the security packet header for the received packet:
  hdr_security_packet* hdr = hdr_security_packet::access(pkt);
  

  // check if in brdcast mode
  if ((u_int32_t)hdrip->daddr() == IP_BROADCAST) 
  {
    if (hdr->ret == 0)
    {
      
      printf("Recv BRDCAST Security_packet REQ : at %d.%d from %d.%d\n", here_.addr_, here_.port_, hdrip->saddr(), hdrip->sport());
      Packet::free(pkt);
      
      // create reply
      Packet* pktret = allocpkt();

      hdr_security_packet* hdrret = hdr_security_packet::access(pktret);
      hdr_cmn* ch = HDR_CMN(pktret);
      hdr_ip* ipret = hdr_ip::access(pktret);
      
      hdrret->ret = 1;
      
      // add brdcast address
      ipret->daddr() = IP_BROADCAST;
      ipret->dport() = ipret->sport();
      send(pktret, 0);    
    }
    else 
    {
      printf("Recv BRDCAST security_packet REPLY : at %d.%d from %d.%d\n", here_.addr_, here_.port_, hdrip->saddr(), hdrip->sport());
      Packet::free(pkt);
    }
    return;
  }
// end of broadcast mode
  
  if (hdr->ret == 0) 
  {
    // Send an 'echo'. First save the old packet's send_time
    double stime = hdr->send_time;
    //---------decrypt encrypted packet-------------//
    char original_data[128];
    char encrypted_data[128];
    strcpy(encrypted_data,hdr->data); //copy the data of the original packet
    strcpy(original_data,hdr->data);
    int rcv_seq = hdr->seq;
    //----------------show the encrypted packet at receiving node-----------//
  	
    char out[105];
    unsigned int newhash;
    char authenticate_result[50];

    // show encryted data then decrytp it and show
     decryption(original_data);
     newhash=hashing(original_data,strlen(original_data));
     if(newhash==hdr->hashvalue)
     {
	printf("data intergity ensured\n");
	strcpy(authenticate_result,"Message_Accepted");
     }
     else
     {
	printf("data modified %d\n",newhash);
	strcpy(authenticate_result,"MESSAGE_ERRROR-Integrity violation");
     }
    sprintf(out, "%s recv %d %3.1f %s %s %d", name(), hdrip->src_.addr_ >> Address::instance().NodeShift_[1],
			(Scheduler::instance().clock()-hdr->send_time) * 1000, encrypted_data, original_data,hdr->hashvalue); 
    Tcl& tcl = Tcl::instance();
    tcl.eval(out);

    // Discard the packet
    Packet::free(pkt);
    // Create a new packet
    Packet* pktret = allocpkt();
    // Access the header for the new packet:
    hdr_security_packet* hdrret = hdr_security_packet::access(pktret);
    // Set the 'ret' field to 1, so the receiver won't send
    // another echo
    hdrret->ret = 1;
    // Set the send_time field to the correct value
    hdrret->send_time = stime;
    
    hdrret->rcv_time = Scheduler::instance().clock();
    hdrret->seq = rcv_seq;
    strcpy(hdrret->data, authenticate_result);//save data to new packet
    // Send the packet back to the originator
    send(pktret, 0);
  }
  else
  {
    char out[105];
     // showing at originator node when packet comes back	
    
    sprintf(out, "%s recv %d %3.1f %s _ %d", name(), hdrip->src_.addr_ >> Address::instance().NodeShift_[1],
			(Scheduler::instance().clock()-hdr->send_time) * 1000, hdr->data, hdr->hashvalue); 
    Tcl& tcl = Tcl::instance();
    tcl.eval(out);
    // Discard the packet
    Packet::free(pkt);
  }
}

