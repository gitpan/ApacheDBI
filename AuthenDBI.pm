package Apache::AuthenDBI;

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED FORBIDDEN DECLINED SERVER_ERROR);
use DBI ();

use strict;

#$Id: AuthenDBI.pm,v 1.32 1999/06/03 08:54:55 mergl Exp $

require_version DBI 0.85;

$Apache::AuthenDBI::VERSION = '0.82';

$Apache::AuthenDBI::DEBUG = 0;


my %Config = (
    'Auth_DBI_data_source'      => '',
    'Auth_DBI_username'         => '',
    'Auth_DBI_password'         => '',
    'Auth_DBI_pwd_table'        => '',
    'Auth_DBI_uid_field'        => '',
    'Auth_DBI_pwd_field'        => '',
    'Auth_DBI_pwd_whereclause'  => '',
    'Auth_DBI_log_field'        => '',
    'Auth_DBI_log_string'       => '',
    'Auth_DBI_authoritative'    => 'on',
    'Auth_DBI_nopasswd'         => 'off',
    'Auth_DBI_encrypted'        => 'on',
    'Auth_DBI_uidcasesensitive' => 'on',
    'Auth_DBI_pwdcasesensitive' => 'on',
    'Auth_DBI_cache_time'       => 0,
    'Auth_DBI_placeholder'      => 'off',
);

# global cache
my %Passwd;
my %Time;


sub handler {

    my ($r) = @_;
    my ($i, $key, $val);

    my ($prefix) = "$$ Apache::AuthenDBI";

    if ($Apache::AuthenDBI::DEBUG) {
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

    # get username
    my ($user_sent) = $r->connection->user;
    print STDERR "$prefix user sent = >$user_sent<\n" if $Apache::AuthenDBI::DEBUG;

    # get configuration
    my $attr = { };
    while(($key, $val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^Auth_DBI_//;
        $attr->{$key} = $val;
        printf STDERR "$prefix Config{ %-16s } = %s\n", $key, $val if $Apache::AuthenDBI::DEBUG;
    }

    # if not configured decline
    unless ($attr->{pwd_table} && $attr->{uid_field} && $attr->{pwd_field}) {
        printf STDERR "$prefix not configured, return DECLINED\n" if $Apache::AuthenDBI::DEBUG;
        return DECLINED;
    }

    # do we want Windows-like case-insensitivity?
    $user_sent = lc($user_sent) if $attr->{uidcasesensitive} eq "off";
    $passwd_sent = lc($passwd_sent) if $attr->{pwdcasesensitive} eq "off";

    # obtain the cache hashes to use:
    my $attr_summary= join $;, $attr->{data_source}, $attr->{pwd_table}, $attr->{uid_field}, $attr->{pwd_whereclause};
    $Passwd{$attr_summary} = {} unless defined $Passwd{$attr_summary};
    $Time{$attr_summary}   = {} unless defined $Time{$attr_summary};
    my $Passwd = $Passwd{$attr_summary};
    my $Time   = $Time{$attr_summary};

    # check whether the user is cached
    my $passwd = $Passwd->{$user_sent};
    # the password might have been changed
    $passwd = '' if $passwd ne $passwd_sent;

    # if password has changed or if it not cached
    if (!$passwd) {
        unless ($attr->{data_source}) {
            $r->log_reason("$prefix missing source parameter for database connect", $r->uri);
            return SERVER_ERROR;
        }

        # connect to database
        my $dbh;
        unless ($dbh = DBI->connect($attr->{data_source}, $attr->{username}, $attr->{password})) {
            $r->log_reason("$prefix db connect error with $attr->{data_source}", $r->uri);
            return SERVER_ERROR;
        }

        # generate statement
        my $user_sent_quoted = $dbh->quote($user_sent);
        my $select    = "SELECT $attr->{pwd_field}";
        my $from      = "FROM $attr->{pwd_table}";
        my $where     = ($attr->{uidcasesensitive} eq "off") ? "WHERE lower($attr->{uid_field}) =" : "WHERE $attr->{uid_field} =";
        my $compare   = ($attr->{placeholder}      eq "on")  ? "?" : "$user_sent_quoted";
        my $statement = "$select $from $where $compare";
        $statement   .= " AND $attr->{pwd_whereclause}" if $attr->{pwd_whereclause};
        print STDERR "$prefix statement = $statement\n" if $Apache::AuthenDBI::DEBUG;

        # prepare statement
        my $sth;
        unless ($sth = $dbh->prepare($statement)) {
            $r->log_reason("$prefix can not prepare statement: $DBI::errstr", $r->uri);
            $dbh->disconnect;
            return SERVER_ERROR;
        }

        # execute statement
        my $rv;
        unless ($rv = ($attr->{placeholder} eq "on") ? $sth->execute($user_sent_quoted) : $sth->execute) {
            $r->log_reason("$prefix can not execute statement: $DBI::errstr", $r->uri);
            $dbh->disconnect;
            return SERVER_ERROR;
        }

        # fetch result
        while ($_ = $sth->fetchrow_array) {
            # strip trailing blanks for fixed-length data-type
            $_ =~ s/ +$// if $_;
            # consider the case with many users sharing the same userid
	    $passwd .= ",$_";
        }
        $passwd =~ s/^,//go;

        $sth->finish;
        $dbh->disconnect;

        # cache userid/password if cache_time is configured
        $Passwd->{$user_sent} = $passwd if $attr->{cache_time} > 0;
    }

    print STDERR "$prefix passwd = >$passwd<\n" if $Apache::AuthenDBI::DEBUG;

    # update timestamp if cache_time is configured
    $Time->{$user_sent} = time if $attr->{cache_time} > 0;

    # check password
    if (!defined($passwd)) {
            # if authoritative insist that user is in database
        if ($attr->{authoritative} eq 'on') {
            $r->log_reason("$prefix Password for user $user_sent not found", $r->uri);
            $r->note_basic_auth_failure;
            return AUTH_REQUIRED;
        } else {
            # else pass control to the next authentication module
            return DECLINED;
        }
    }

    # allow no password
    if ($attr->{nopasswd} eq 'on' && ! length($passwd)) {
        return OK;
    }

    # if nopasswd is off, reject user
    unless (length($passwd_sent) && length($passwd)) {
        $r->log_reason("$prefix user $user_sent: empty password(s) rejected", $r->uri);
        $r->note_basic_auth_failure;
        return AUTH_REQUIRED;
    }

    # check password
    my $found = 0;
    my $password;
    foreach $password (split(/,/, $passwd)) {
        # compare the two passwords possibly crypting the password if needed
        if (($attr->{encrypted} eq 'on' and crypt($passwd_sent, $password) eq $password) or $passwd_sent eq $password) {
            $found = 1;
            last;
        }
    }
    unless ($found) {
        $r->log_reason("$prefix user $user_sent: password mismatch", $r->uri);
        $r->note_basic_auth_failure;
        return AUTH_REQUIRED;
    }

    # after finishing the request the handler checks the password-cache and deletes any outdated entry
    # note: the CleanupHandler runs after the response has been sent to the client
    if($attr->{cache_time} > 0 && Apache->can('push_handlers')) {
        print STDERR "$$ Apache::AuthenDBI push PerlCleanupHandler \n" if $Apache::AuthenDBI::DEBUG;
        Apache->push_handlers("PerlCleanupHandler", sub {
            print STDERR "$$ Apache::AuthenDBI PerlCleanupHandler \n" if $Apache::AuthenDBI::DEBUG;
            my ($user, $diff);
            foreach $user (keys %$Passwd) {
                $diff = time - $Time->{$user};
                if ($diff >= $attr->{cache_time}) {
                    print STDERR "$$ Apache::AuthenDBI delete $user from cache, last access before $diff seconds \n" if $Apache::AuthenDBI::DEBUG;
                    delete $Passwd->{$user};
                    delete $Time->{$user};
                }
            }
        });
    }

    # logging option
    if ($attr->{log_field} && $attr->{log_string}) {
        my $dbh;
        unless ($dbh = DBI->connect($attr->{data_source}, $attr->{username}, $attr->{password})) {
            $r->log_reason("$prefix db connect error with $attr->{data_source}", $r->uri);
            return SERVER_ERROR;
        }
        my $user_sent_quoted = $dbh->quote($user_sent);
        my $statement = "UPDATE $attr->{pwd_table} SET $attr->{log_field} = $attr->{log_string} WHERE $attr->{uid_field}=$user_sent_quoted";
        print STDERR "$prefix statement = $statement\n" if $Apache::AuthenDBI::DEBUG;
        unless ($dbh->do($statement)) {
            $r->log_reason("$prefix can not do statement: $DBI::errstr", $r->uri);
            $dbh->disconnect;
            return SERVER_ERROR;
        }
        $dbh->disconnect;
    }

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

 require valid-user

The AuthType is limited to Basic. The require directive is limited 
to 'valid-user'. For 'user user_1 user_2 ...' and for group support 
see AuthzDBI.pm.


=head1 DESCRIPTION

This module allows authentication against a database using Perl's DBI. 
For supported DBI drivers see: 

 http://www.symbolstone.org/technology/perl/DBI/

For the given username the password is looked up in the cache. If it is not 
found in the cache, it is requested from the database. 

If the username does not exist and the authoritative directive is set to 'on', 
the request is rejected. If the authoritative directive is set to 'off', the 
control is passed on to next module in line. 

If the password for the given username is empty and the nopasswd directive 
is set to 'off', the request is rejected. If the nopasswd directive is set 
to 'on', any password is accepted. 

Finally the passwords (multiple passwords per userid are allowed) retrieved 
from the database are compared to the password given. If the encrypted 
directive is set to 'on', the given password is encrypted using perl's crypt() 
function before comparison. If the encrypted directive is set to 'off' the 
plain-text passwords are compared. 

If this comparison fails the request is rejected, otherwise the request is 
accepted. 

The SQL-select used for retrieving the passwords is as follows: 

 SELECT pwd_field FROM pwd_table WHERE uid_field = user

If a pwd_whereclause exists, it is appended to the SQL-select.

At the end a CleanupHandler is initialized, which skips through the password 
cache and deletes all outdated entries. This is done after sending the response, 
hence without slowing down response time to the client. The default cache_time 
is set to 0, which disables the cache, because any user will be deleted 
immediately from the cache. 

This module supports in addition a simple kind of logging mechanism. Whenever 
the handler is called and a log_string is configured, the log_field will be 
updated with the log_string. As log_string - depending upon the database - 
macros like TODAY can be used. 

The SQL-select used for the logging mechanism is as follows: 

 UPDATE pwd_table SET log_field = log_string WHERE uid_field = user

 
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
Auth_DBI_pwd_whereclause

Use this option for specifying more constraints to the SQL-select.

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

=item *
Auth_DBI_uidcasesensitive  < on / off >

Default is 'on'. When set 'off', the entered userid is converted to lower case. 
Also the userid in the password select-statement is converted to lower case. 

=item *
Auth_DBI_pwdcasesensitive  < on / off >

Default is 'on'. When set 'off', the entered password is converted to lower case. 

=item *
Auth_DBI_cache_time

Default is 0 = off. When set to any value n > 0, the passwords of all users will 
be cached for n seconds. After finishing the request, a special handler skips 
through the cache and deletes all outdated entries (entries, which are older than 
the cache_time). 

=item *

Auth_DBI_placeholder < on / off >
Default is 'off'.  When set 'on', the select statement is prepared using a placeholder 
for the username.  This may result in improved performance for databases supporting this method.
 

=head1 CONFIGURATION

The module should be loaded upon startup of the Apache daemon.
Note that this needs mod_perl-1.08 or higher, apache_1.3.0 or higher and that 
mod_perl needs to be configured with 

  PERL_AUTHEN=1 PERL_CLEANUP=1 PERL_STACKED_HANDLERS=1. 

Add the following line to your httpd.conf or srm.conf:

 PerlModule Apache::AuthenDBI


=head1 PREREQUISITES

For Apache::AuthenDBI you need to enable the appropriate call-back hooks when 
making mod_perl: 

  perl Makefile.PL PERL_AUTHEN=1 PERL_CLEANUP=1 PERL_STACKED_HANDLERS=1. 


=head1 SECURITY

In some cases it is more secure not to put the username and the 
password in the .htaccess file. The following example shows a 
solution to this problem:

httpd.conf:

 <Perl>
 my($uid,$pwd) = My::dbi_pwd_fetch();
 $Location{'/foo/bar'}->{PerlSetVar} = [
     [ Auth_DBI_username  => $uid ],
     [ Auth_DBI_password  => $pwd ],
 ];
 </Perl>


=head1 SEE ALSO

L<Apache>, L<mod_perl>, L<DBI>


=head1 AUTHORS

=item *
mod_perl by Doug MacEachern <dougm@telebusiness.co.nz>

=item *
DBI by Tim Bunce <Tim.Bunce@ig.co.uk>

=item *
Apache::AuthenDBI by Edmund Mergl <E.Mergl@bawue.de>


=head1 COPYRIGHT

The Apache::AuthenDBI module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
