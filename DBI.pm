package Apache::DBI;

use strict;
use DBI ();

my(%Connected);

sub new {
    bless [@_] => shift;
}

sub connect {
    my($self, @args) = @_;
    my $idx = join ":", (@args) || (@{$self});
    return $Connected{$idx} if $Connected{$idx};
    print "connecting to $idx...\n" if $DBI::dbi_debug;
    $Connected{$idx} = DBI->connect(@args);
}

sub drh {
    my($self, $driver) = @_;
    $DBI::installed_drh{$driver};
}

sub DESTROY {
}

1;

__END__

=head1 NAME

Apache::DBI - persistent database connection via DBI

=head1 SYNOPSIS

 use Apache::DBI;

 $dbh = Apache::DBI->connect(...);

=head1 DESCRIPTION

This module provides a persistent database connection via DBI. 
For supported DBI drivers see: 

 http://www.hermetica.com/technologia/DBI/

All you really need is to replace DBI with Apache::DBI. 
When connecting to a database the module looks if a database 
handle from a previous connect request is already stored. If 
not, a new connection is established and the handle is stored 
for later re-use. The destroy method has been intentionally 
left empty. 

=head1 SEE ALSO

Apache(3), DBI(3)

=head1 AUTHORS

 DBI by Tim Bunce <Tim.Bunce@ig.co.uk>
 mod_perl by Doug MacEachern <dougm@osf.org>
 Apache::DBI by Edmund Mergl <E.Mergl@bawue.de>
