#-----------------------------------
# Dated: April 25,2005
# Created: Sam Tran and Tuan Nguyen.
# File name: security_packet.cc
#-----------------------------------
#Create a simulator object
set ns [new Simulator]

#Define different colors for data flows (for NAM)
$ns color 1 Blue
$ns color 2 Red

#Open a trace file
set nf [open out.nam w]
$ns namtrace-all $nf

#Define a 'finish' procedure
proc finish {} {
        global ns nf
        $ns flush-trace
        close $nf
        exec nam out.nam &
        exit 0
}

#Create four nodes
set n0 [$ns node]
set n1 [$ns node]
set n2 [$ns node]
set n3 [$ns node]
set n4 [$ns node]
set n5 [$ns node]

#Create links between the nodes
$ns duplex-link $n0 $n2 5Mb 10ms DropTail
$ns duplex-link $n1 $n2 5Mb 10ms DropTail
$ns duplex-link $n2 $n3 1.5Mb 10ms DropTail
$ns duplex-link $n3 $n4 5Mb 10ms DropTail
$ns duplex-link $n3 $n5 5Mb 10ms DropTail

#Set Queue Size of link (n2-n3) to 100
$ns queue-limit $n2 $n3 100

$ns duplex-link-op $n0 $n2 orient right-down
$ns duplex-link-op $n1 $n2 orient right-up
$ns duplex-link-op $n2 $n3 orient right
$ns duplex-link-op $n3 $n4 orient right-up
$ns duplex-link-op $n3 $n5 orient right-down

#Define a 'recv' function for the class 'Agent/Security_packet'
Agent/Security_packet instproc recv {from rtt mess originmess hash} {
	$self instvar node_
	puts "node [$node_ id] received packet from \
              $from with trip-time $rtt ms - contend: $mess - decrypted $originmess -hash: $hash"
}

#Create two security agents and attach them to the nodes n0 and n2
set p0 [new Agent/Security_packet]
$ns attach-agent $n0 $p0
$p0 set class_ 1

set p1 [new Agent/Security_packet]
$ns attach-agent $n1 $p1
$p1 set class_ 1

set p2 [new Agent/Security_packet]
$ns attach-agent $n4 $p2
$p2 set class_ 2

set p3 [new Agent/Security_packet]
$ns attach-agent $n5 $p3
$p3 set class_ 2

#Connect the two agents
$ns connect $p0 $p3
$ns connect $p1 $p2


#Schedule events

for {set i 1} {$i < 2} {incr i} {
	set result [expr $i /2]
	$ns at $result "$p0 send itisalongmessageIcansend" 
	$ns at [expr $result + 0.02] "$p1 send  Itisashotermessage"
	$ns at [expr $result + 0.04] "$p2 send test3"
	$ns at [expr $result + 0.06] "$p3 send test4"
}
$ns at 1.0 "finish"

#Run the simulation
$ns run
