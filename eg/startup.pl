#!/usr/local/bin/perl

# example startup script for persistent database connections

# make sure we are in a sane environment.
$ENV{GATEWAY_INTERFACE} =~ /^CGI-Perl/ or die "GATEWAY_INTERFACE not Perl!";

use Apache::Registry;
use Apache::Status;
use Apache::DBI;
#use Apache::AuthenDBI;
#use Apache::AuthzDBI;
#use Apache::DebugDBI;

# configure here all connections which should be established during server startup
#Apache::DBI->connect_on_init("dbi:driver:database", "userid", "passwd");

# optionally configure the ping behavior of the persistent database connections
# $timeout = 0  -> always ping the database connection (default)
# $timeout < 0  -> never  ping the database connection
# $timeout > 0  -> ping the database connection only if the last access
#                  was more than timeout seconds before
#Apache::DBI->setPingTimeOut("dbi:driver:database", $timeout);

1;
