#!/usr/local/bin/perl

# make sure we are in a sane environment.
$ENV{GATEWAY_INTERFACE} =~ /^CGI-Perl/ or die "GATEWAY_INTERFACE not Perl!";

use Apache::Registry;
use Apache::Status;
use Apache::DBI;
#use Apache::AuthenDBI;
#use Apache::AuthzDBI;
#use Apache::DebugDBI;

# you need to configure mod_perl with PERL_CHILD_INIT=1 and 
# PERL_STACKED_HANDLERS=1 for connect_on_init
# adapt this to your environment:
Apache::DBI->connect_on_init("dbi:driver:database", "userid", "passwd");

1;

