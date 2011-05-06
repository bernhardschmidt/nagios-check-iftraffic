#!/usr/bin/perl -w
#
# check_iftraffic.pl - Nagios(r) network traffic monitor plugin
# Copyright (C) 2004 Gerd Mueller / Netways GmbH
# $Id: check_iftraffic.pl 1119 2006-02-09 10:30:09Z gmueller $
#
# mw = Markus Werner mw+nagios@wobcom.de
# Remarks (mw):
#
#	I adopted as much as possible the programming style of the origin code.
#
#	There should be a function to exit this programm,
#	instead of calling print and exit statements all over the place.
#
#
# minor changes by mw
# 	The snmp if_counters on net devices can have overflows.
#	I wrote this code to address this situation.
#	It has no automatic detection and which point the overflow
#	occurs but it will generate a warning state and you
#	can set the max value by calling this script with an additional
#	arg.
#
# minor cosmetic changes by mw
#	Sorry but I couldn't sustain to clean up some things.
#
# gj = Greg Frater gregATfraterfactory.com
# Remarks (gj):
# minor (gj):
# 
#	* fixed the performance data, formating was not to spec
# 	* Added a check of the interfaces status (up/down).
#	  If down the check returns a critical status.
# 	* Allow either textual or the numeric index value.
#	* If the interface speed is not specified on the command line
#	  it gets it automatically from IfSpeed
#	* Added option for second ifSpeed to allow for asymetrcal links
#	  such as a DSL line or cable modem where the download and upload
#	  speeds are different
#	* Added -B option to display results in bits/sec instead of Bytes/sec
#	* Added the current usage in Bytes/s (or bit/s) to the perfdata output
#	* Added ability for plugin to determine interface to query by matching IP 
#	  address of host with entry in ipAdEntIfIndex (.1.3.6.1.2.1.4.20.1.2) 
#	* Added -L flag to list entries found in the ipAdEntIfIndex table
#	Otherwise, it works as before.
#
#
#
#
# based on check_traffic from Adrian Wieczorek, <ads (at) irc.pila.pl>
#
# Send us bug reports, questions and comments about this plugin.
# Latest version of this software: http://www.nagiosexchange.org
#
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307

use strict;

use Net::SNMP;
use Getopt::Long;
&Getopt::Long::config('bundling');

use Data::Dumper;

my $host_ip;
my $host_address;
my $iface_number;
my $iface_descr;
my $iface_speed;
my $iface_speedOut;
my $index_list;
my $opt_h;
my $units;

my $session;
my $error;
my $port         = 161;
my $snmp_version = 1;

my @snmpoids;

# SNMP OIDs for Traffic
my $snmpIfOperStatus 	= '1.3.6.1.2.1.2.2.1.8';
my $snmpIfInOctets  	= '1.3.6.1.2.1.2.2.1.10';
my $snmpIfOutOctets 	= '1.3.6.1.2.1.2.2.1.16';
my $snmpIfDescr     	= '1.3.6.1.2.1.2.2.1.2';
my $snmpIfSpeed     	= '1.3.6.1.2.1.2.2.1.5';
my $snmpIPAdEntIfIndex 	= '1.3.6.1.2.1.4.20.1.2';

my $response;

# Path to  tmp files
my $TRAFFIC_FILE = "/tmp/traffic";

# changes sos 20090717 UNKNOWN must bes 3
my %STATUS_CODE =
  ( 'UNKNOWN' => '3', 'OK' => '0', 'WARNING' => '1', 'CRITICAL' => '2' );

#default values;
my $state = "UNKNOWN";
my $if_status = '4';
my ( $in_bytes, $out_bytes ) = 0;
my $warn_usage = 85;
my $crit_usage = 98;
my $COMMUNITY  = "public";
my $use_reg    =  undef;  # Use Regexp for name
my $output = "";
my $bits = undef; 
my $suffix = "Bs";
my $label = "MBytes";

#added 20050614 by mw
my $max_value;
my $max_bytes;

#cosmetic changes 20050614 by mw, see old versions for detail
# Added options for bits and second max ifspeed 20100202 by gj
# Added options for specificy IP addr to match 20100405 by gj
my $status = GetOptions(
	"h|help"        => \$opt_h,
	'B'		=> \$bits,
	'bits'		=> \$bits,
	"C|community=s" => \$COMMUNITY,
	"w|warning=s"   => \$warn_usage,
	"c|critical=s"  => \$crit_usage,
	"b|bandwidth|I|inBandwidth=i" => \$iface_speed,
	"O|outBandwidth=i" => \$iface_speedOut,
        'r'             => \$use_reg,           
        'noregexp'      => \$use_reg,
	"p|port=i"      => \$port,
	"u|units=s"     => \$units,
	"i|interface=s" => \$iface_descr,
	"A|address=s"   => \$host_ip,
	"H|hostname=s"  => \$host_address,
	'L'	  	=> \$index_list,
	'list'	  	=> \$index_list,

	#added 20050614 by mw
	"M|max=i" => \$max_value
);

if ( $status == 0 ) {
	print_help();
	exit $STATUS_CODE{'OK'};
}

# Changed 20091214 gj
# Check for missing options
#if ( ( !$host_address ) or ( !$iface_descr ) ) {
if ( !$host_address )  {
	print  "\nMissing host address!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $iface_speed ) and ( !$units ) ){
	print "\nMissing units!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $units ) and ( ( !$iface_speed ) and  ( !$iface_speedOut ) ) ) {
	print "\nMissing interface maximum speed!\n\n";
	stop(print_usage(),"OK");
} elsif ( ( $iface_speedOut ) and ( !$units ) ) {
	print "\nMissing units for Out maximum speed!\n\n";
	stop(print_usage(),"OK");
}


if ($bits) {
	$suffix = "bs"
}

if ( !$iface_speed ) {
	# Do nothing
}else{

	#change 20050414 by mw
	# Added iface_speedOut 20100202 by gj
	# Convert interface speed to kiloBytes
	$iface_speed = bits2bytes( $iface_speed, $units ) / 1024;
	if ( $iface_speedOut ) {
		$iface_speedOut = bits2bytes( $iface_speedOut, $units ) / 1024;
	}
	if ( !$max_value ) {
	
		# If no -M Parameter was set, set it to 32Bit Overflow
		$max_bytes = 4194304 ;    # the value is (2^32/1024)
	}
	else {
		$max_bytes = unit2bytes( $max_value, $units );
	}
}

if ( $snmp_version =~ /[12]/ ) {
	( $session, $error ) = Net::SNMP->session(
		-hostname  => $host_address,
		-community => $COMMUNITY,
		-port      => $port,
		-version   => $snmp_version
	);

	if ( !defined($session) ) {
		stop("UNKNOWN: $error","UNKNOWN");
	}
}
elsif ( $snmp_version =~ /3/ ) {
	$state = 'UNKNOWN';
	stop("$state: No support for SNMP v3 yet\n",$state);
}
else {
	$state = 'UNKNOWN';
	stop("$state: No support for SNMP v$snmp_version yet\n",$state);
}

# Neither Interface Index nor Host IP address were specified 
if ( !$iface_descr ) {
	if ( !$host_ip ){
		# try to resolve host name and find index from ip addr
		$iface_descr = fetch_Ip2IfIndex( $session, $host_address );
	} else {
		# Use ip addr to find index
		$iface_descr = fetch_Ip2IfIndex( $session, $host_ip );
	}	
}

#push( @snmpoids, $snmpIPAdEntIfIndex . "." . $host_address );

# Added 20091209 gj
# Detect if a string description was given or a numberic interface index number 
if ( $iface_descr =~ /[^0123456789]+/ ) {
	$iface_number = fetch_ifdescr( $session, $iface_descr );
}else{
	$iface_number = $iface_descr;
}

push( @snmpoids, $snmpIfSpeed . "." . $iface_number );
push( @snmpoids, $snmpIfOperStatus . "." . $iface_number );
push( @snmpoids, $snmpIfInOctets . "." . $iface_number );
push( @snmpoids, $snmpIfOutOctets . "." . $iface_number );

if ( !defined( $response = $session->get_request(@snmpoids) ) ) {
	my $answer = $session->error;
	$session->close;

	stop("WARNING: SNMP error: $answer\n", "WARNING");
}

# Added 20091209 gj
# Get interface speed from device if not provided on command line
# Convert to kiloBytes
if ( !$iface_speed ) { 
	$iface_speed = $response->{ $snmpIfSpeed . "." . $iface_number };
	$units = "b";
	$iface_speed = bits2bytes( $iface_speed, $units ) / 1024;
}

# Added 20100201 gj
# Check if Out max speed was provided, use same if speed for both if not
if (!$iface_speedOut) {
	$iface_speedOut = $iface_speed;
}

$if_status = $response->{ $snmpIfOperStatus . "." . $iface_number };
$in_bytes  = $response->{ $snmpIfInOctets . "." . $iface_number } / 1024; # in kiloBytes
$out_bytes = $response->{ $snmpIfOutOctets . "." . $iface_number } / 1024; # in kiloBytes

$session->close;

my $row;
my $last_check_time = time - 1;
my $last_in_bytes   = $in_bytes;
my $last_out_bytes  = $out_bytes;

if (
	open( FILE,
		"<" . $TRAFFIC_FILE . "_if" . $iface_number . "_" . $host_address
	)
  )
{
	while ( $row = <FILE> ) {

		#cosmetic change 20050416 by mw
		#Couldn't sustain;-)
##		chomp();
		( $last_check_time, $last_in_bytes, $last_out_bytes ) =
		  split( ":", $row );

		### by sos 17.07.2009 check for last_bytes
		if ( ! $last_in_bytes  ) { $last_in_bytes=$in_bytes;  }
		if ( ! $last_out_bytes ) { $last_out_bytes=$out_bytes; }

		if ($last_in_bytes !~ m/\d/) { $last_in_bytes=$in_bytes; }
		if ($last_out_bytes !~ m/\d/) { $last_out_bytes=$out_bytes; }
	}
	close(FILE);
}

my $update_time = time;

open( FILE, ">" . $TRAFFIC_FILE . "_if" . $iface_number . "_" . $host_address )
  or die "Can't open $TRAFFIC_FILE for writing: $!";

printf FILE ( "%s:%.0ld:%.0ld\n", $update_time, $in_bytes, $out_bytes );
close(FILE);

my $db_file;

#added 20050614 by mw
#Check for and correct counter overflow (if possible).
#See function counter_overflow.
$in_bytes  = counter_overflow( $in_bytes,  $last_in_bytes,  $max_bytes );
$out_bytes = counter_overflow( $out_bytes, $last_out_bytes, $max_bytes );

# Calculate traffic since last check (RX\TX) in kiloBytes
my $in_traffic = sprintf( "%.2lf",
	( $in_bytes - $last_in_bytes ) / ( time - $last_check_time ) );
my $out_traffic = sprintf( "%.2lf",
	( $out_bytes - $last_out_bytes ) / ( time - $last_check_time ) );

# sos 20090717 changed  due to rrdtool needs bytes
my $in_traffic_absolut  = $in_bytes * 1024 ;
my $out_traffic_absolut = $out_bytes * 1024;

# Calculate usage percentages
my $in_usage  = sprintf( "%.2f", ( 1.0 * $in_traffic * 100 ) / $iface_speed );
my $out_usage = sprintf( "%.2f", ( 1.0 * $out_traffic * 100 ) / $iface_speedOut );


if ($bits) {
	# Convert output from Bytes to bits
	$in_bytes = $in_bytes * 8;
	$out_bytes = $out_bytes * 8;
	$in_traffic = $in_traffic * 8;
	$out_traffic = $out_traffic * 8;	
	$label = "Mbits";
}

my $in_prefix  = "K";
my $out_prefix = "K";

if ( $in_traffic > 1024 ) {
	$in_traffic = sprintf( "%.2f", $in_traffic / 1024 );
	$in_prefix = "M";
}
if ( $out_traffic > 1024 ) {
	$out_traffic = sprintf( "%.2f", $out_traffic / 1024 );
	$out_prefix = "M";
}
if ( $in_traffic > 1024 * 1024 ) {
	$in_traffic = sprintf( "%.2f", $in_traffic / 1024 * 1024 );
	$in_prefix = "G";
}
if ( $out_traffic > 1024 * 1024 ) {
	$out_traffic = sprintf( "%.2f",$out_traffic / 1024 * 1024 );
	$out_prefix = "G";
}

# Convert from kiloBytes to megaBytes
$in_bytes  = sprintf( "%.2f", $in_bytes / 1024 );
$out_bytes = sprintf( "%.2f", $out_bytes / 1024 );

$state = "OK";

# Added 20091209 by gj
if ( $if_status != 1 ) {
	$output = "Interface $iface_descr is down!";
	
}else{
	$output =
	"Average IN: "
	  . $in_traffic . $in_prefix . $suffix . " (" . $in_usage . "%), " 
	  . "Average OUT: " . $out_traffic . $out_prefix . $suffix . " (" . $out_usage . "%)<br>";
	$output .= "Total RX: $in_bytes $label, Total TX: $out_bytes $label";
}

# Changed 20091209 gj
if ( ( $in_usage > $crit_usage ) or ( $out_usage > $crit_usage ) or ( $if_status != 1 ) ) {
	$state = "CRITICAL";
}

if (   ( $in_usage > $warn_usage )
	or ( $out_usage > $warn_usage ) && $state eq "OK" )
{
	$state = "WARNING";
}

# Changed 20091209 gj
$output = "$state - $output"
  if ( $state ne "OK" );

# Changed 20091214 gj - commas should have been semi colons
$output .=
"|inUsage=$in_usage%;$warn_usage;$crit_usage outUsage=$out_usage%;$warn_usage;$crit_usage"
  . " inBandwidth=" . $in_traffic . $in_prefix . $suffix . " outBandwidth=" . $out_traffic . $out_prefix . $suffix 
  . " inAbsolut=$in_traffic_absolut outAbsolut=$out_traffic_absolut";

stop($output, $state);


sub fetch_Ip2IfIndex {
	my $state;
	my $response;

	my $snmpkey;
	my $answer;
	my $key;

	my ( $session, $host ) = @_;


	# Determine if we have a host name or IP addr
	if ( $host =~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ){
		#print "\nI found an IP address\n\n";
	} else {
		$host = get_ip ( $host );
		#print "\nWe have a host name $host\n\n";
	}

	# Quit if results not found
	if ( !defined( $response = $session->get_table($snmpIPAdEntIfIndex) ) ) {
		$answer = $session->error;
		$session->close;
		$state = 'CRITICAL';
		$session->close;
		exit $STATUS_CODE{$state};
	}

	
	my %resp = %{$response};
#	foreach $key ( keys %{$response} ) {

		if ( $index_list ){
			print ("\nInterfaces found:\n");
			print ("  IP Addr\tIndex\n");
			print ("------------------------\n");
		}		
	# Check each returned value
	foreach $key ( keys %resp ) {

		if ( $index_list ){
			my $index_addr = substr $key, 21;
			print ($index_addr,"\t ",$resp{$key},"\n");
		}

		# Check for ip address mathcin in returned index results
		if ( $key =~ /$host$/ ) {
			$snmpkey = $resp{$key};
		}
	}
	unless ( defined $snmpkey ) {
		$session->close;
		$state = 'CRITICAL';
		printf "$state: Could not match $host \n";
		exit $STATUS_CODE{$state};
	}
	return $snmpkey;
}

sub fetch_ifdescr {
	my $state;
	my $response;

	my $snmpkey;
	my $answer;
	my $key;

	my ( $session, $ifdescr ) = @_;

	if ( !defined( $response = $session->get_table($snmpIfDescr) ) ) {
		$answer = $session->error;
		$session->close;
		$state = 'CRITICAL';
		$session->close;
		exit $STATUS_CODE{$state};
	}

	foreach $key ( keys %{$response} ) {

		# added 20070816 by oer: remove trailing 0 Byte for Windows :-(
		my $resp=$response->{$key};
		$resp =~ s/\x00//;


                my $test = defined($use_reg)
                      ? $resp =~ /$ifdescr/
                      : $resp eq $ifdescr;

                if ($test) {

		###if ( $resp =~ /^$ifdescr$/ ) {
		###if ( $resp =~ /$ifdescr/ ) {
                ### print "$resp  \n";
		###if ( $response->{$key} =~ /^$ifdescr$/ ) {

			$key =~ /.*\.(\d+)$/;
			$snmpkey = $1;

			# print "$ifdescr = $key / $snmpkey \n";  #debug
		}
	}
	unless ( defined $snmpkey ) {
		$session->close;
		$state = 'CRITICAL';
		printf "$state: Could not match $ifdescr \n";
		exit $STATUS_CODE{$state};
	}
	return $snmpkey;
}

#added 20050416 by mw
#Converts an input value to value in bits
sub bits2bytes {
	return unit2bytes(@_) / 8;
}

#added 20050416 by mw
#Converts an input value to value in bytes
sub unit2bytes {
	my ( $value, $unit ) = @_;

	if ( $unit eq "g" ) {
		return $value * 1024 * 1024 * 1024;
	}
	elsif ( $unit eq "m" ) {
		return $value * 1024 * 1024;
	}
	elsif ( $unit eq "k" ) {
		return $value * 1024;
	}
	elsif ( $unit eq "b" ) {
		return $value * 1;
	}
	else {
		print "You have to supply a supported unit\n";
		exit $STATUS_CODE{'UNKNOWN'};
	}
}

#added 20050414 by mw
#This function detects if an overflow occurs. If so, it returns
#a computed value for $bytes.
#If there is no counter overflow it simply returns the origin value of $bytes.
#IF there is a Counter reboot wrap, just use previous output.
sub counter_overflow {
	my ( $bytes, $last_bytes, $max_bytes ) = @_;

	$bytes += $max_bytes if ( $bytes < $last_bytes );
	$bytes = $last_bytes  if ( $bytes < $last_bytes );
	return $bytes;
}

# Added 20100202 by gj
# Print results and exit script
sub stop {
	my $result = shift;
	my $exit_code = shift;
	print $result . "\n";
	exit ( $STATUS_CODE{$exit_code} );
}

# Added 20100405 by gj
# Lookup hosts ip address
sub get_ip {
	use Net::DNS;

	my ( $host_name ) = @_;

	my $res = Net::DNS::Resolver->new;
	my $query = $res->search($host_name);

	if ($query) {
		foreach my $rr ($query->answer) {
			next unless $rr->type eq "A";
			#print $rr->address, "\n";
			return $rr->address;
		}
	} else {
		
		stop("Error: IP address not resolved\n","UNKNOWN");
	}
}

#cosmetic changes 20050614 by mw
#Couldn't sustain "HERE";-), either.
sub print_usage {
	print <<EOU;
    Usage: check_iftraffic3.pl -H host [ -C community_string ] [ -i if_index|if_descr ] [ -r ] [ -b if_max_speed_in | -I if_max_speed_in ] [ -O if_max_speed_out ] [ -u ] [ -B ] [ -A IP Address ] [ -L ] [ -M ] [ -w warn ] [ -c crit ]

    Example 1: check_iftraffic3.pl -H host1 -C sneaky
    Example 2: check_iftraffic3.pl -H host1 -C sneaky -i "Intel Pro" -r -B  
    Example 3: check_iftraffic3.pl -H host1 -C sneaky -i 5
    Example 4: check_iftraffic3.pl -H host1 -C sneaky -i 5 -B -b 100 -u m 
    Example 5: check_iftraffic3.pl -H host1 -C sneaky -i 5 -B -b 20 -O 5 -u m 
    Example 6: check_iftraffic3.pl -H host1 -C sneaky -A 192.168.1.1 -B -b 100 -u m 

    Options:

    -H, --host STRING or IPADDRESS
        Check interface on the indicated host.
    -B, --bits
	Display results in bits per second b/s (default: Bytes/s)
    -C, --community STRING 
        SNMP Community.
    -r, --regexp
        Use regexp to match NAME in description OID
    -i, --interface STRING
        Interface Name
    -b, --bandwidth INTEGER
    -I, --inBandwidth INTEGER
        Interface maximum speed in kilo/mega/giga/bits per second.  Applied to 
	both IN and OUT if no second (-O) max speed is provided.
    -O, --outBandwidth INTEGER
        Interface maximum speed in kilo/mega/giga/bits per second.  Applied to
	OUT traffic.  Uses the same units value given for -b. 
    -u, --units STRING
        g=gigabits/s,m=megabits/s,k=kilobits/s,b=bits/s.  Required if -b, -I, or 
	-O are used.
    -w, --warning INTEGER
        % of bandwidth usage necessary to result in warning status (default: 85%)
    -c, --critical INTEGER
        % of bandwidth usage necessary to result in critical status (default: 98%)
    -M, --max INTEGER
	Max Counter Value of net devices in kilo/mega/giga/bytes.
    -A, --address STRING (IP Address)
	IP Address to use when determining the interface index to use.  Can be 
	used when the index changes frequently or as in the case of Windows 
	servers the index is different depending on the NIC installed.
    -L, --list FLAG (on/off)
	Tell plugin to list available interfaces. This is not supported inside 
	of Nagios, but may be useful from the command line.
EOU

}

