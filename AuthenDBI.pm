package Apache::AuthenDBI;

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use DBI ();

use strict;

#$Id: AuthenDBI.pm,v 1.7 1997/05/20 20:09:37 mergl Exp $

require_version DBI 0.81;

my $VERSION = '0.6';

my $DEBUG = $ENV{APACHE_AUTHENDBI_DEBUG} || 0;


my %Config = (
    'AuthDBIDB'            => '',
    'AuthDBIUser'          => '',
    'AuthDBIAuth'          => '',
    'AuthDBIDriver'        => '',
    'AuthDBINameField'     => '',
    'AuthDBIPasswordField' => '',
    'AuthDBIUserTable'     => '',
);

sub handler {

    my($r) = @_;

    print STDERR "\nApache::AuthenDBI::handler\n" if $DEBUG;

    return OK unless $r->is_initial_req; #only the first internal request

    # here the dialog pops up and asks you for userid and password
    my($res, $passwd_sent) = $r->get_basic_auth_pw;
    print STDERR "get_basic_auth = $res, password sent = $passwd_sent\n" if $DEBUG;
    return $res if $res; # e.g. HTTP_UNAUTHORIZED

    my($key, $val);
    my $attr = { };
    while(($key, $val) = each %Config) {
	$val = $r->dir_config($key) || $val;
	$key =~ s/^AuthDBI//;
	$attr->{$key} = $val;
        printf STDERR "Config{ %-15s } = %s\n", $key, $val if $DEBUG;
    }

    my $dbh;
    unless ($dbh = DBI->connect($attr->{DB}, $attr->{User}, $attr->{Auth}, $attr->{Driver})) {
	$r->log_reason("db connect error with $attr->{DB}", $r->uri);
	$r->note_basic_auth_failure;
	return SERVER_ERROR;
    }

    my $user_sent = $dbh->quote($r->connection->user);
    print STDERR "user sent = $user_sent, password sent = $passwd_sent \n" if $DEBUG;

    my $statement = "SELECT $attr->{PasswordField} from $attr->{UserTable} WHERE $attr->{NameField}=$user_sent";
    print STDERR "statement = $statement\n" if $DEBUG;

    my $sth;
    unless ($sth = $dbh->prepare($statement)) {
	$r->log_reason("can not prepare statement: $DBI::errstr", $r->uri);
	$r->note_basic_auth_failure;
	return SERVER_ERROR;
    }

    my $rc;
    unless ($rc = $sth->execute) {
	$r->log_reason("can not execute statement: $DBI::errstr", $r->uri);
	$r->note_basic_auth_failure;
	return SERVER_ERROR;
    }

    my @row = $sth->fetchrow;
    print STDERR "row = @row \n" if $DEBUG;

    $sth->finish;

    my $passwd;
    unless ($passwd = $row[0]) {
	$r->log_reason("User $user_sent not found", $r->uri);
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    unless (crypt($passwd_sent, $passwd) eq $passwd) {
	$r->log_reason("user $user_sent: password mismatch", $r->uri);
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    $dbh->disconnect if !($INC{'Apache.pm'});

    return OK;
}


1;

__END__

=head1 NAME

Apache::AuthenDBI - Authentication via Perl's DBI

=head1 SYNOPSIS

 # Configuration in httpd.conf or srm.conf

 PerlModule Apache::AuthenDBI

 # Authentication in .htaccess

 AuthName DBI
 AuthType Basic

 #authenticate via DBI
 PerlAuthenHandler Apache::AuthenDBI

 PerlSetVar AuthDBIDB     dbname
 PerlSetVar AuthDBIUser   username
 PerlSetVar AuthDBIAuth   auth
 PerlSetVar AuthDBIDriver driver
 #DBI->connect(DB, User, Auth, Driver)

 PerlSetVar AuthDBIUserTable table
 PerlSetVar AuthDBINameField user
 PerlSetVar AuthDBIPasswordField password
 #SELECT PasswordField from UserTable WHERE NameField='$user_sent'

 <Limit GET POST>
 require valid-user
 </Limit>

The AuthType is limited to Basic. The require directive is limited to 'valid-user' 
and 'user xxx' (no group support). 

=head1 DESCRIPTION

This module allows the Apache server to authenticate against a database. 
It should be used together with Apache::DBI.pm to gain the benefit of a
persistent database connection. Remember that the authentification accesses 
the database once for every request !  Make sure, that in httpd.conf or 
srm.conf the module Apache::DBI comes first:

 PerlModule Apache::DBI
 PerlModule Apache::AuthenDBI

The authentification module makes use of persistent connections only 
if the appropriate module Apache::DBI is already loaded ! 


The database access uses Perl's DBI. For supported DBI drivers see: 

 http://www.hermetica.com/technologia/DBI/

=head1 SEE ALSO

Apache(3), DBI(3)

=head1 AUTHORS

 mod_perl by Doug MacEachern <dougm@osf.org>
 DBI by Tim Bunce <Tim.Bunce@ig.co.uk>
 Apache::AuthenDBI by Edmund Mergl <E.Mergl@bawue.de>
