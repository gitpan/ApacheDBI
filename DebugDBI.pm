package Apache::DebugDBI;

#$Id: DebugDBI.pm,v 1.3 1997/12/18 20:24:59 mergl Exp $

$Apache::DebugDBI::VERSION = '0.76';

$Apache::AuthenDBI::DEBUG = 1;
$Apache::AuthzDBI::DEBUG  = 1;
$Apache::DBI::DEBUG       = 1;

1;

__END__


=head1 NAME

Apache::DebugDBI - Debug Apache::DBI modules


=head1 SYNOPSIS

 # Configuration in httpd.conf or srm.conf:

 PerlModule Apache::DebugDBI # this comes after all other Apache modules


=head1 DESCRIPTION

This module turns on debugging output in the Apache::DBI modules. 


=head1 AUTHORS

Apache::DebugDBI by Edmund Mergl <E.Mergl@bawue.de>


=head1 COPYRIGHT

The Apache::DebugDBI module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut

