#
# PacketGen v1.3
# packet_generator.pl
# this script read tcpdump file with cpan Net::Pcap
# then send the correspondence packet to the designated IP address through socket
# 
# 1.1 version 08_11_2013
# 1.2 version 10_11_2013 ++ add packetlen to cut trailer, install Math::BaseCnv
# 1.3 version 13_2_2014 ++ read from configuration file
# 
# created by Syafiq Al Atiiq ~ syafiq.atiiq@dimensiondata.com
# 

#!/usr/bin/perl -w

#use strict;
use Net::Pcap;
use IO::Socket::INET;
use String::HexConvert ':all';
use Math::BaseCnv;
use Switch;
use Config::Simple;

my $pcap = undef;
my $err  = '';
my $count = 0;

$cfg = new Config::Simple('packetgen.conf');

# Read from configuration file 
my $apps = $cfg->param('apps');
my $ipdest = $cfg->param('ipdest');
my $portdest = $cfg->param('portdest');
my $protocol = $cfg->param('proto');
my $file = $cfg->param('pcapfile');
my $counter = $cfg->param('counter');

# counter for different packet
switch ($apps) {
	case gtp {
		$packcount = 46;
	}
	case diameter {
		$packcount = 70;
	}
}

sub process_packet {
	$count++;
	my ($user_data, $header_ref, $packet) = @_;
	
	# Start socket
	$| = 1;

	# socket initiation
	my $socket = new IO::Socket::INET (
		PeerHost => $ipdest,
		PeerPort => $portdest,
		Proto => $protocol 
	);
	die "cannot connect to the server $!\n" unless $socket;
	print "connected to the server\n";	

	# sending file
	my $req = $packet;
	$req = ascii_to_hex($packet);
	@packet_split = ( $req =~ m/../g );
	# my $maxpacket = scalar(@packet_split);
	# where is the packet length located
	my $packetlen_hex = $packet_split[$packcount+2].$packet_split[$packcount+3];
	#print "$packetlen_hex \n";
	# packet len in GTP should be added by 8 to get real length
	my $packetlen_dec = (cnv($packetlen_hex,16,10))+8;
	print "packet length : $packetlen_dec \n";
	my @packet_specific = splice(@packet_split, $packcount, $packetlen_dec);
	$packet_send = join "", @packet_specific;
	$packet_send = hex_to_ascii($packet_send);
	# print "\n@packet_specific \n";
	my $size = $socket->send($packet_send);
	#$socket->send($packet_send);
	print "sent data of length $size\n";
	#print "debug \n";
	# notify server that request has been sent
	shutdown($socket, 1);

	# closing socket
	$socket->close();	

}

$pcap = Net::Pcap::open_offline($file, \$err)
        or die "Can't read '$file': $err\n";

Net::Pcap::loop($pcap, $counter, \&process_packet, '');

Net::Pcap::close($pcap);

print "Number of packets = $count\n";
