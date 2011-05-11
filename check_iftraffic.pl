#!/usr/bin/perl -w
#
# check_iftraffic.pl - Nagios(r) network traffic monitor plugin
# Copyright (C) 2004 Gerd Mueller / Netways GmbH
# based on check_traffic from Adrian Wieczorek, <ads (at) irc.pila.pl>
# Changes made by 
# 	Markus Werner mw+nagios@wobcom.de (Version 1.0 to 2.0)
# 	Greg Frater gregATfraterfactory.com (Version 3.0)
# 	Ektanoor (Version 4.0 to 4.1)
# 	Bernhard Schmidt berni@birkenwald.de (Version 5.0+)
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

#For perl 5.12. We use it.
#use 5.012;

#For perl 5.10
use feature qw(switch say);

#For older versions of perl
#use Switch;

use strict;

use Net::SNMP;

use Data::Dumper;
use Nagios::Plugin;

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
my $snmp_version = 2;

my @snmpoids;

# SNMP OIDs for Traffic
my $snmpIfOperStatus = '1.3.6.1.2.1.2.2.1.8';

#Older 32-bit counter:
#my $snmpIfInOctets  	= '1.3.6.1.2.1.2.2.1.10';
my $snmpIfInOctets = '1.3.6.1.2.1.31.1.1.1.6';

#Older 32-bit counter:
#my $snmpIfOutOctets 	= '1.3.6.1.2.1.2.2.1.16';
my $snmpIfOutOctets    = '1.3.6.1.2.1.31.1.1.1.10';
my $snmpIfDescr        = '1.3.6.1.2.1.2.2.1.2';
my $snmpIfSpeed        = '1.3.6.1.2.1.2.2.1.5';
my $snmpIPAdEntIfIndex = '1.3.6.1.2.1.4.20.1.2';

my $response;

# Path to  tmp files
my $TRAFFIC_FILE = "/tmp/traffic";

#default values;
my $state     = "UNKNOWN";
my $if_status = '4';
my ( $in_bits, $out_bits ) = 0;
my $warn_usage;
my $crit_usage;
my $COMMUNITY;
my $port;
my $output     = "";
my $bytes      = undef;
my $suffix     = "bps";
my $label      = "Bytes";

my $max_value;
my $max_bits;

my $np;
my $threshold;

#Need to check this
my $use_reg = undef;    # Use Regexp for name

sub bytes2bits {
    return unit2bytes(@_) * 8;
}

#Converts an input value to value in bytes
sub unit2bytes {
    my ( $value, $unit ) = @_;
    given ($unit) {
        when ('G') { return $value * 1073741824; }
        when ('M') { return $value * 1048576; }
        when ('K') { return $value * 1024; }
        default    { return $value }
    };
}

sub unit2bits {
    my ( $value, $unit ) = @_;
    given ($unit) {
        when ('g') { return $value * 1000000000; }
        when ('m') { return $value * 1000000; }
        when ('k') { return $value * 1000; }
        default    { return $value }
    };
}

# Added 20100405 by gj
# Lookup hosts ip address
sub get_ip {
    use Net::DNS;

    my ($host_name) = @_;
    my $res         = Net::DNS::Resolver->new;
    my $query       = $res->search($host_name);

    if ($query) {
        foreach my $rr ( $query->answer ) {
            next unless $rr->type eq "A";
            return $rr->address;
        }
    }
    else {
        $np->nagios_die( "Error: IP address not resolved" );
    }
}

sub fetch_Ip2IfIndex {
    my $response;
    my $snmpkey;
    my $answer;
    my $key;

    my ( $session, $host ) = @_;

    # Determine if we have a host name or IP addr
    if ( $host !~ /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ ) {
        $host = get_ip($host);
    }

    # Quit if results not found
    if ( !defined( $response = $session->get_table($snmpIPAdEntIfIndex) ) ) {
        $answer = $session->error;
        $session->close;
        $np->nagios_die( "SNMP error: $answer", "CRITICAL" );
    }

    my %resp = %{$response};
    foreach $key ( keys %resp ) {

        # Check for ip address mathcin in returned index results
        if ( $key =~ /$host$/ ) {
            $snmpkey = $resp{$key};
        }
    }
    unless ( defined $snmpkey ) {
        $session->close;
        $np->nagios_die( "Could not match $host", "CRITICAL" );
    }
    return $snmpkey;
}

sub fetch_ifdescr {
    my $response;
    my $snmpkey;
    my $answer;
    my $key;

    my ( $session, $ifdescr ) = @_;

    if ( !defined( $response = $session->get_table($snmpIfDescr) ) ) {
        $answer = $session->error;
        $session->close;
        $np->nagios_die( "SNMP error: $answer", "CRITICAL" );
    }

    foreach $key ( keys %{$response} ) {

        # added 20070816 by oer: remove trailing 0 Byte for Windows :-(
        my $resp = $response->{$key};
        $resp =~ s/\x00//;

        my $test = defined($use_reg) ? $resp =~ /$ifdescr/ : $resp eq $ifdescr;

        if ($test) {
            $key =~ /.*\.(\d+)$/;
            $snmpkey = $1;
        }
    }
    unless ( defined $snmpkey ) {
        $session->close;
        $np->nagios_die( "Could not match $ifdescr", "CRITICAL" );
    }
    return $snmpkey;
}

sub format_volume {
    my $prefix_x;
    my ($x) = @_;

    if ( $x > 1000000000000000000 ) {
        $x        = $x / 1000000000000000000;
        $prefix_x = "E";
    }
    if ( $x > 1000000000000000 ) {
        $x        = $x / 1000000000000000;
        $prefix_x = "P";
    }
    if ( $x > 1000000000000 ) {
        $x        = $x / 1000000000000;
        $prefix_x = "T";
    }
    if ( $x > 1000000000 ) {
        $x        = $x / 1000000000;
        $prefix_x = "G";
    }
    if ( $x > 1000000 ) {
        $x        = $x / 1000000;
        $prefix_x = "M";
    }
    if ( $x > 1000 ) {
        $x        = $x / 1000;
        $prefix_x = "K";
    }
    $x = sprintf( "%.2f", $x );
    return $x . $prefix_x;
}

sub format_volume_bytes {
    my $prefix_x;
    my ($x) = @_;

    if ( $x > 1152921504606846976 ) {
        $x        = $x / 1152921504606846976;
        $prefix_x = "E";
    }
    if ( $x > 1125899906842624 ) {
        $x        = $x / 1125899906842624;
        $prefix_x = "P";
    }
    if ( $x > 1099511627776 ) {
        $x        = $x / 1099511627776;
        $prefix_x = "T";
    }
    if ( $x > 1073741824 ) {
        $x        = $x / 1073741824;
        $prefix_x = "G";
    }
    if ( $x > 1048576 ) {
        $x        = $x / 1048576;
        $prefix_x = "M";
    }
    if ( $x > 1024 ) {
        $x        = $x / 1024;
        $prefix_x = "K";
    }
    $x = sprintf( "%.2f", $x );
    return $x . $prefix_x;
}

$np = Nagios::Plugin->new(
	usage => "%s -H host [ -C community_string ] [ -p port ] [ -i if_index|if_descr ] [ -r ] [ -b if_max_speed_in | -I if_max_speed_in ] [ -O if_max_speed_out ] [ -u ] [ -B ] [ -A IP Address ] [ -L ] [ -M ] [ -w warn ] [ -c crit ] [ --total ]",
	version => "5.0",
	url => "https://github.com/bernhardschmidt/nagios-check-iftraffic",
	blurb => "Check traffic on an interface using SNMP",
	plugin => "check_iftraffic.pl",
	timeout => 10,
	extra => "\n\n" .
		"Example 1: check_iftraffic.pl -H host1 -C sneaky\n" .
		"Example 2: check_iftraffic.pl -H host1 -C sneaky -i \"Intel Pro\" -r -B\n" .
		"Example 3: check_iftraffic.pl -H host1 -C sneaky -i 5\n" . 
		"Example 4: check_iftraffic.pl -H host1 -C sneaky -i 5 -B -b 100 -u m\n" .
		"Example 5: check_iftraffic.pl -H host1 -C sneaky -i 5 -B -b 20 -O 5 -u m\n" .
		"Example 6: check_iftraffic.pl -H host1 -C sneaky -A 192.168.1.1 -B -b 100 -u m\n",
);

$np->add_arg(
	spec	=> 'bytes|B',
	help	=> "Display results in Bytes per second B/s (default: bits/s)",
);

$np->add_arg(
	spec	=> 'hostname|H=s',
	help	=> 'Host name or IP address (required)',
	required	=> 1,
	label	=> 'ADDRESS'
);

$np->add_arg(
	spec	=> 'community|C=s',
	help	=> "SNMP Community (default: %s)",
	default	=> "public",
);

$np->add_arg(
	spec	=> 'port|p=i',
	help	=> "SNMP Port (default: %s)",
	default	=> 161
);

$np->add_arg(
	spec	=> 'interface|i=s',
	help	=> [
		'Interface Name',
		'Interface Index',
	],
	label	=> ['STRING', 'INTEGER'],
);

$np->add_arg(
	spec	=> 'bandwidth|b|I|inBandwidth=i',
	help	=> "Interface maximum speed in kilo/mega/giga/bits per second.  Applied to\n" .
		"   both IN and OUT if no second (-O) max speed is provided. (default: autodetect)"
);

$np->add_arg(
	spec	=> 'outBandwidth|O=i',
	help	=> "Interface maximum speed in kilo/mega/giga/bits per second.  Applied to\n" .
		"   OUT traffic.  Uses the same units value given for -b."
);

$np->add_arg(
	spec	=> 'regexp|r=s',
	help	=> "Use regexp to match NAME in description OID"
);

$np->add_arg(
	spec	=> 'units|u=s',
	help	=> "g=gigabits/s,m=megabits/s,k=kilobits/s,b=bits/s.  Required if -b, -I, or\n" .
		"   -O are used. (default: %s)",
	default	=> "b",
);

$np->add_arg(
	spec	=> 'warning|w=i',
	help	=> "% of bandwidth usage necessary to result in warning status (default: %s\%)",
	default	=> 85,
);

$np->add_arg(
	spec	=> 'critical|c=i',
	help	=> "% of bandwidth usage necessary to result in critical status (default: %s\%)",
	default	=> 98,
);

$np->add_arg(
	spec	=> 'max|M=i',
	help	=> "Max Counter Value of net devices in kilo/mega/giga/bytes.",
);

$np->add_arg(
    spec 	=> 'address|A=s',
    help	=> "IP Address to use when determining the interface index to use.  Can be\n" .
	"   used when the index changes frequently or as in the case of Windows\n" .
	"   servers the index is different depending on the NIC installed.",
    label	=> 'IPADDRESS',
);

$np->add_arg(
    spec    => 'total',
    help    => "Display total (absolute) amount of traffic in output and perfdata";
);

$np->getopts();

$threshold = $np->set_thresholds(
	warning		=> $np->opts->warning,
	critical	=> $np->opts->critical
);


# Legacy variable assignments
$host_ip = $np->opts->address;
$bytes = $np->opts->bytes;
$iface_speed = $np->opts->bandwidth;
$COMMUNITY = $np->opts->community;
$crit_usage = $np->opts->critical;
$host_address = $np->opts->hostname;
$iface_descr = $np->opts->interface;
$max_value = $np->opts->max;
$iface_speedOut = $np->opts->outBandwidth;
$port = $np->opts->port;
$use_reg = $np->opts->regexp;
$units = $np->opts->units;
$warn_usage = $np->opts->warning;

# Check for missing options
if ( ($iface_speed) and ($bytes) ) {
    $iface_speed = bytes2bits( $iface_speed, $units );
    if ($iface_speedOut) {
        $iface_speedOut = bytes2bits( $iface_speedOut, $units );
    }
}
elsif ($iface_speed) {
    $iface_speed = unit2bits( $iface_speed, $units );
    if ($iface_speedOut) {
        $iface_speedOut = unit2bits( $iface_speedOut, $units );
    }
}

# If no -M Parameter was set, set it to 64Bit Overflow
if ( !$max_value ) {
    $max_bits = 18446744073709551616;
}
else {
    if ( !$bytes ) {
        $max_bits = unit2bits( $max_value, $units );
    }
    else {
        $max_bits = bytes2bits( $max_value, $units );
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
        $np->nagios_die( $error );
    }
}
elsif ( $snmp_version =~ /3/ ) {
    $np->nagios_die( "No support for SNMPv3 yet" );
}
else {
    $np->nagios_die( "Unknown SNMP version: $snmp_version" );
}

# Neither Interface Index nor Host IP address were specified
if ( !$iface_descr ) {
    if ( !$host_ip ) {

        # try to resolve host name and find index from ip addr
        $iface_descr = fetch_Ip2IfIndex( $session, $host_address );
    }
    else {

        # Use ip addr to find index
        $iface_descr = fetch_Ip2IfIndex( $session, $host_ip );
    }
}

# Detect if a string description was given or a numberic interface index number
if ( $iface_descr =~ /[^0123456789]+/ ) {
    $iface_number = fetch_ifdescr( $session, $iface_descr );
}
else {
    $iface_number = $iface_descr;
}

push( @snmpoids, $snmpIfSpeed . "." . $iface_number );
push( @snmpoids, $snmpIfOperStatus . "." . $iface_number );
push( @snmpoids, $snmpIfInOctets . "." . $iface_number );
push( @snmpoids, $snmpIfOutOctets . "." . $iface_number );

if ( !defined( $response = $session->get_request(@snmpoids) ) ) {
    my $answer = $session->error;
    $session->close;
    $np->nagios_die( "SNMP error: $answer", "WARNING" );
}

if ( !$iface_speed ) {
    $iface_speed = $response->{ $snmpIfSpeed . "." . $iface_number };
}

# Check if Out max speed was provided, use same if speed for both if not
if ( !$iface_speedOut ) {
    $iface_speedOut = $iface_speed;
}

$if_status = $response->{ $snmpIfOperStatus . "." . $iface_number };
$in_bits   = $response->{ $snmpIfInOctets . "." . $iface_number } * 8;
$out_bits  = $response->{ $snmpIfOutOctets . "." . $iface_number } * 8;

#We retain the absolute values in bytes for RRD. It doesn't matter that the counter may overflow.
my $in_traffic_absolut  = $response->{ $snmpIfInOctets . "." . $iface_number };
my $out_traffic_absolut = $response->{ $snmpIfOutOctets . "." . $iface_number };

$session->close;

my $update_time     = time;
my $last_check_time = $update_time - 1;

if ( $if_status != 1 ) {
    $np->nagios_die( "SNMP error: Interface $iface_descr is down!",
        "CRITICAL" );
}

my $row;
my $last_in_bits  = $in_bits;
my $last_out_bits = $out_bits;

if (
    open( FILE,
        "<" . $TRAFFIC_FILE . "_if" . $iface_number . "_" . $host_address
    )
  )
{
    while ( $row = <FILE> ) {
        ( $last_check_time, $last_in_bits, $last_out_bits ) =
          split( ":", $row );
        if ( !$last_in_bits )          { $last_in_bits  = $in_bits; }
        if ( !$last_out_bits )         { $last_out_bits = $out_bits; }
        if ( $last_in_bits !~ m/\d/ )  { $last_in_bits  = $in_bits; }
        if ( $last_out_bits !~ m/\d/ ) { $last_out_bits = $out_bits; }
    }
    close(FILE);
}

if (
    open( FILE,
        ">" . $TRAFFIC_FILE . "_if" . $iface_number . "_" . $host_address
    )
  )
{
    printf FILE ( "%s:%.0ld:%.0ld\n", $update_time, $in_bits, $out_bits );
    close(FILE);
}

my $in_traffic  = 0;
my $out_traffic = 0;

if ( $in_bits < $last_in_bits ) {
    $in_bits    = $in_bits + ( $max_bits - $last_in_bits );
    $in_traffic = $in_bits / ( $update_time - $last_check_time );
}
else {
    $in_traffic =
      ( $in_bits - $last_in_bits ) / ( $update_time - $last_check_time );
}

if ( $out_bits < $last_out_bits ) {
    $out_bits    = $out_bits + ( $max_bits - $last_out_bits );
    $out_traffic = $out_bits / ( $update_time - $last_check_time );
}
else {
    $out_traffic =
      ( $out_bits - $last_out_bits ) / ( $update_time - $last_check_time );
}

# Calculate usage percentages
my $in_usage  = ( $in_traffic * 100 ) / $iface_speed;
my $out_usage = ( $out_traffic * 100 ) / $iface_speedOut;

if ($bytes) {

    # Convert output from bits to bytes
    $in_traffic  = $in_traffic / 8;
    $out_traffic = $out_traffic / 8;
    $suffix      = "Bs";
}

my $in  = format_volume($in_traffic);
my $out = format_volume($out_traffic);

my $rx = format_volume_bytes($in_traffic_absolut);
my $tx = format_volume_bytes($out_traffic_absolut);

#Convert percentages to a more visual format
$in_usage  = sprintf( "%.2f", $in_usage );
$out_usage = sprintf( "%.2f", $out_usage );

#Convert performance to a more visual format
$in_traffic  = sprintf( "%.2f", $in_traffic );
$out_traffic = sprintf( "%.2f", $out_traffic );

$output =
    "Average IN: " 
  . $in 
  . $suffix . " ("
  . $in_usage . "%), "
  . "Average OUT: "
  . $out
  . $suffix . " ("
  . $out_usage . "%) ";

if ($np->opts->total) {
    $output .= "Total RX: " . $rx . $label . ", Total TX: " . $tx . $label;
};

$state = Nagios::Plugin::OK;

$state = $np->max_state($state, $np->check_threshold( $in_usage ));
$state = $np->max_state($state, $np->check_threshold( $out_usage ));

$np->add_perfdata(
	label	=> "inUsage",
	value	=> $in_usage,
	uom	=> '%',
	threshold => $threshold );

$np->add_perfdata(
	label	=> "outUsage",
	value	=> $out_usage,
	uom	=> '%',
	threshold => $threshold );

$np->add_perfdata(
	label	=> "inBandwidth",
	value	=> $in_traffic,
	uom	=> $suffix );

$np->add_perfdata(
	label	=> "outBandwidth",
	value	=> $out_traffic,
	uom	=> $suffix );

if ($np->opts->total) {
    $np->add_perfdata(
        label	=> "inAbsolut",
        value	=> $in_traffic_absolut );
    $np->add_perfdata(
        label	=> "outAbsolut",
        value	=> $out_traffic_absolut );
};

$np->nagios_exit( $state, $output );

