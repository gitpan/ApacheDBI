#!/usr/local/bin/perl

# make sure we are in a sane environment.
$ENV{GATEWAY_INTERFACE} =~ /^CGI-Perl/ or die "GATEWAY_INTERFACE not Perl!";

use Apache::Registry;
use Apache::DBI;
#use Apache::AuthenDBI;
#use Apache::AuthzDBI;
#use Apache::DebugDBI;

# adapt this to your environment:
Apache::DBI->connect_on_init("dbi:driver:database", "userid", "passwd");

1;

