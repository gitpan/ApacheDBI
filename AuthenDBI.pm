package Apache::AuthenDBI;

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use DBI ();

use strict;

#$Id: AuthenDBI.pm,v 1.10 1997/08/15 13:33:44 mergl Exp $

require_version DBI 0.85;

$Apache::AuthenDBI::VERSION = '0.74';

$Apache::AuthenDBI::DEBUG = 0;


my %Config = (
    'Auth_DBI_data_source'    => '',
    'Auth_DBI_username'       => '',
    'Auth_DBI_password'       => '',
    'Auth_DBI_pwd_table'      => '',
    'Auth_DBI_uid_field'      => '',
    'Auth_DBI_pwd_field'      => '',
    'Auth_DBI_log_field'      => '',
    'Auth_DBI_log_string'     => '',
    'Auth_DBI_authoritative'  => 'on',
    'Auth_DBI_nopasswd'       => 'off',
    'Auth_DBI_encrypted'      => 'on',
);

sub handler {

    my ($r) = @_;
    my ($i, $key, $val);

    my ($prefix) = "$$ Apache::AuthenDBI";

    if ( $Apache::AuthenDBI::DEBUG ) {
        my ($type) = '';
        $type .= 'initial ' if $r->is_initial_req;
        $type .= 'main'     if $r->is_main;
        print STDERR "\n==========\n$prefix request type = $type\n";
    }

    return OK unless $r->is_initial_req; # only the first internal request

    print STDERR "REQUEST:\n", $r->as_string if $Apache::AuthenDBI::DEBUG;

    # here the dialog pops up and asks you for username and password
    my($res, $passwd_sent) = $r->get_basic_auth_pw;
    print STDERR "$prefix get_basic_auth_pw: res = >$res<, password sent = >$passwd_sent<\n" if $Apache::AuthenDBI::DEBUG;
    return $res if $res; # e.g. HTTP_UNAUTHORIZED

    my ($user_sent) = $r->connection->user;
    print STDERR "$prefix user sent = >$user_sent<\n" if $Apache::AuthenDBI::DEBUG;

    # get configuration
    my $attr = { };
    while(($key, $val) = each %Config) {
	$val = $r->dir_config($key) || $val;
	$key =~ s/^Auth_DBI_//;
	$attr->{$key} = $val;
        printf STDERR "$prefix Config{ %-15s } = %s\n", $key, $val if $Apache::AuthenDBI::DEBUG;
    }

    # if not configured decline
    unless ( $attr->{pwd_table} && $attr->{uid_field} && $attr->{pwd_field} ) {
        printf STDERR "$prefix not configured, return DECLINED\n" if $Apache::AuthenDBI::DEBUG;
        return DECLINED;
    }

    unless ( $attr->{data_source} ) {
        $r->log_reason("$prefix missing source parameter for database connect", $r->uri);
        return SERVER_ERROR;
    }

    # connect to database
    my $dbh;
    unless ($dbh = DBI->connect($attr->{data_source}, $attr->{username}, $attr->{password})) {
        $r->log_reason("$prefix db connect error with $attr->{data_source}", $r->uri);
        return SERVER_ERROR;
    }

    $user_sent  = $dbh->quote($user_sent);

    my $statement = "SELECT $attr->{pwd_field} FROM $attr->{pwd_table} WHERE $attr->{uid_field}=$user_sent";
    print STDERR "$prefix statement = $statement\n" if $Apache::AuthenDBI::DEBUG;

    # prepare statement
    my $sth;
    unless ($sth = $dbh->prepare($statement)) {
	$r->log_reason("$prefix can not prepare statement: $DBI::errstr", $r->uri);
	return SERVER_ERROR;
    }

    # execute statement
    my $rv;
    unless ($rv = $sth->execute) {
	$r->log_reason("$prefix can not execute statement: $DBI::errstr", $r->uri);
	return SERVER_ERROR;
    }

    # fetch result
    my ($passwd) = $sth->fetchrow_array;
    print STDERR "$prefix passwd = >$passwd<\n" if $Apache::AuthenDBI::DEBUG;

    $sth->finish;

    # check password
    if ( ! defined($passwd) ) {
            # if authoritative insist that user is in database
        if ( $attr->{authoritative} eq 'on' ) {
	    $r->log_reason("$prefix Password for user $user_sent not found", $r->uri);
	    $r->note_basic_auth_failure;
	    return AUTH_REQUIRED;
	} else {
            # else pass control to the next authentication module
	    return DECLINED;
        }
    }

    # allow no password
    if ( $attr->{nopasswd} eq 'on' && ! length($passwd) ) {
        return OK;
    }

    # if nopasswd is off, reject user
    unless ( length($passwd_sent) && length($passwd) ) {
	$r->log_reason("$prefix user $user_sent: empty password(s) rejected", $r->uri);
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    # check here is crypt is needed
    if ( $attr->{encrypted} eq 'on' ) {
        my ($salt) = substr($passwd, 0, 2);
        $passwd_sent = crypt($passwd_sent, $salt);
    }

    # check password
    unless ($passwd_sent eq $passwd) {
	$r->log_reason("$prefix user $user_sent: password mismatch", $r->uri);
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    # logging option
    if ( $attr->{log_field} && $attr->{log_string} ) {
        $statement = "UPDATE $attr->{pwd_table} SET $attr->{log_field} = $attr->{log_string} WHERE $attr->{uid_field}=$user_sent";
        print STDERR "$prefix statement = $statement\n" if $Apache::AuthenDBI::DEBUG;
        unless ($dbh->do($statement)) {
            $r->log_reason("$prefix can not do statement: $DBI::errstr", $r->uri);
            return SERVER_ERROR;
        }
    }

    $dbh->disconnect;

    printf STDERR "$prefix return OK\n" if $Apache::AuthenDBI::DEBUG;
    return OK;
}


1;

__END__


=head1 NAME

Apache::AuthenDBI - Authentication via Perl's DBI


=head1 SYNOPSIS

 # Configuration in httpd.conf or srm.conf:

 PerlModule Apache::AuthenDBI

 # Authentication in .htaccess:

 AuthName DBI
 AuthType Basic

 #authenticate via DBI
 PerlAuthenHandler Apache::AuthenDBI

 PerlSetVar Auth_DBI_data_source   dbi:driver:dsn
 PerlSetVar Auth_DBI_username      db_username
 PerlSetVar Auth_DBI_password      db_password
 #DBI->connect($data_source, $username, $password)

 PerlSetVar Auth_DBI_pwd_table     users
 PerlSetVar Auth_DBI_uid_field     username
 PerlSetVar Auth_DBI_pwd_field     password
 #SELECT pwd_field FROM pwd_table WHERE uid_field=$user

 <Limit GET>
 require valid-user
 </Limit>

The AuthType is limited to Basic. The require directive is limited 
to 'valid-user' and 'user user_1 user_2 ...'. For group support see 
AuthzDBI.pm.


=head1 DESCRIPTION

This module allows authentication against a database using Perl's DBI. 
For supported DBI drivers see: 

 http://www.hermetica.com/technologia/DBI/

For the given username the password is looked up in the database. 

If the username does not exist and the authoritative directive is set to 'on', 
the request is rejected. If the authoritative directive is set to 'off', the 
control is passed on to next module in line. 

If the password for the given username is empty and the nopasswd directive 
is set to 'off', the request is rejected. If the nopasswd directive is set 
to 'on', any password is accepted. 

Finally the password retrieved from the database is compared to the password 
given. If the encrypted directive is set to 'on', the given password is 
encrypted using perl's crypt() function before comparison. If the encrypted 
directive is set to 'off' the plain-text passwords are compared. 

If this comparison fails the request is rejected, otherwise the request is 
accepted. 

This module supports in addition a simple kind of logging mechanism. Whenever 
the handler is called and a log_string is configured, the log_field will be 
updated with the log_string. As log_string - depending upon the database - 
macros like TODAY can be used. 


=head1 LIST OF TOKENS

=item *
Auth_DBI_data_source

The data_source value should begin with 'dbi:driver_name:'. This value 
(with the 'dbi:...:' prefix removed) is passed to the database driver for 
processing during connect. 

=item *
Auth_DBI_username

The username argument is passed to the database driver for processing during 
connect.

=item *
Auth_DBI_password

The password argument is passed to the database driver for processing during 
connect.

=item *
Auth_DBI_pwd_table

Contains at least the fields with the username and the (encrypted) password. 
The username should be unique. 

=item *
Auth_DBI_uid_field

Field name containing the username in the Auth_DBI_pwd_table. 

=item *
Auth_DBI_pwd_field

Field name containing the password in the Auth_DBI_pwd_table. 

=item *
Auth_DBI_log_field

Field name containing the log string in the Auth_DBI_pwd_table. 

=item *
Auth_DBI_log_string

String to update the Auth_DBI_log_field in the Auth_DBI_pwd_table. Depending 
upon the database this can be a macro like 'TODAY'. 

=item *
Auth_DBI_authoritative  < on / off>

Default is 'on'. When set 'on', there is no fall-through to other 
authentication methods if the authentication check fails. When this directive 
is set to 'off', control is passed on to any other authentication modules. Be 
sure you know what you are doing when you decide to switch it off. 

=item *
Auth_DBI_nopasswd  < on / off >

Default is 'off'. When set 'on' the password comparison is skipped if the 
Auth_DBI_pwd_field is empty, i.e. allow any password. This is 'off' by default 
to ensure that an empty Auth_DBI_pwd_field does not allow people to log in 
with a random password. Be sure you know what you are doing when you decide to 
switch it on. 

=item *
Auth_DBI_encrypted  < on / off >

Default is 'on'. When set 'on', the value in the Auth_DBI_pwd_field is assumed 
to be crypted using perl's crypt() function and the incoming password is 
crypted before comparison. When this directive is set to 'off', the comparison 
is done directly with the plain-text entered password. 


=head1 CONFIGURATION

The module should be loaded upon startup of the Apache daemon.
Add the following line to your httpd.conf or srm.conf:

 PerlModule Apache::AuthenDBI


=head1 PREREQUISITES

For AuthenDBI you need to enable the appropriate call-back hook 
when making mod_perl: 

  perl Makefile.PL PERL_AUTHEN=1. 


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

The Apache::AuthenDBI module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
