package Apache::DBI;

use DBI ();
use strict;

#$Id: DBI.pm,v 1.5 1997/08/15 13:33:45 mergl Exp $

require_version DBI 0.85;

$Apache::DBI::VERSION = '0.74';

$Apache::DBI::DEBUG = 0;


my %Connected;

sub connect {

    my $class = shift;
    unshift @_, $class if ref $class;
    my $drh  = shift;
    my @args = map { defined $_ ? $_ : "" } @_;
    my $idx  = join (":", (@args));

    if (($Connected{$idx} && $Connected{$idx}->ping)) {
        print STDERR "$$ Apache::DBI already connected to '$idx'\n" if $Apache::DBI::DEBUG;
        return (bless $Connected{$idx}, 'Apache::DBI::db');
    }

    $Connected{$idx} = undef;
    $Connected{$idx} = $drh->connect(@args);
    return undef if ! $Connected{$idx};
    $Connected{$idx}->{InactiveDestroy} = 1;
    print STDERR "$$ Apache::DBI new connect to '$idx'\n" if $Apache::DBI::DEBUG;
    return (bless $Connected{$idx}, 'Apache::DBI::db');
}


{ package Apache::DBI::db;
  no strict;
  @ISA=qw(DBI::db);
  use strict;
  sub disconnect {1};
}


Apache::Status->menu_item(

    'DBI' => 'DBI connections',
    sub {
        my($r, $q) = @_;
        my(@s) = qw(<TABLE><TR><TD>Datasource</TD><TD>Username</TD></TR>);
        for (keys %Connected) {
            push @s, '<TR><TD>', join('</TD><TD>', (split(':', $_))[0,1]), "</TD></TR>\n";
        }
        push @s, '</TABLE>';
        return \@s;
   }

) if ($INC{'Apache.pm'} && Apache->module('Apache::Status'));


1;

__END__


=head1 NAME

Apache::DBI - Initiate a persistent database connection


=head1 SYNOPSIS

 # Configuration in httpd.conf or srm.conf:

 PerlModule Apache::DBI  # this comes before all other Apache modules


=head1 DESCRIPTION

This module initiates a persistent database connection. 

The database access uses Perl's DBI. For supported DBI drivers see: 

 http://www.hermetica.com/technologia/DBI/

When loading the DBI module (do not confuse this with the Apache::DBI module) 
it looks if the environment variable GATEWAY_INTERFACE starts with 'CGI-Perl' 
and if the module Apache::DBI has been loaded. In this case every connect 
request will be forwarded to the Apache::DBI module. This looks if a database 
handle from a previous connect request is already stored and if this handle is 
still valid using the ping method. If these two conditions are fulfilled it 
just returns the database handle. If there is no appropriate database handle 
or if the ping method fails, a new connection is established and the handle is 
stored for later re-use. There is no need to delete the disconnect statements 
from your code. They won't do anything because the Apache::DBI module 
overloads the disconnect method with a NOP. 

The Apache::DBI module still has a limitation: it keeps database connections 
persistent on a per process basis. The problem is, if a user accesses several 
times a database, the http requests will be handled very likely by different 
httpd children. Every child process needs to do its own connect. It would be 
nice, if all httpd children could share the database handles. One possible 
solution might be a threaded Apache version. 

With this limitation in mind, there are scenarios, where the usage of 
Apache::DBI.pm is depreciated. Think about a heavy loaded Web-site where every 
user connects to the database with a unique userid. Every httpd child would 
create many database handles each of which spawning a new backend process. 
In a short time this would kill the web server. 

Another problem are timeouts: some databases disconnect the client after a 
certain time of inactivity. The module tries to validate the database handle 
using the new ping-method of the DBI-module. This method returns true as 
default. If the database handle is not valid and the driver module has no 
implementation for the ping method, you will get an error when accessing the 
database. As a work-around you can try to replace the ping method by any 
database command, which is cheap and safe. 

This module plugs in a menu item for Apache::Status. The menu lists the 
current database connections. It should be considered incomplete because of 
the limitations explained above. It shows the current database connections 
for one specific httpd process, the one which happens to serve the current 
request. Other httpd children might have other database connections. 


=head1 CONFIGURATION

The module should be loaded upon startup of the Apache daemon.
Add the following line to your httpd.conf or srm.conf:

 PerlModule Apache::DBI

It is important, to load this module before any other Apache module ! 


=head1 SEE ALSO

L<Apache>, L<mod_perl>, L<DBI>


=head1 AUTHORS

=item *
mod_perl by Doug MacEachern <dougm@osf.org>

=item *
DBI by Tim Bunce <Tim.Bunce@ig.co.uk>

=item *
Apache::AuthenDBI by Edmund Mergl <E.Mergl@bawue.de>


=head1 COPYRIGHT

The Apache::DBI module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
