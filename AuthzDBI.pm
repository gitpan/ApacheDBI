package Apache::AuthzDBI;

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use DBI ();

use strict;

#$Id: AuthzDBI.pm,v 1.5 1997/08/15 13:33:44 mergl Exp $

require_version DBI 0.85;

$Apache::AuthzDBI::VERSION = '0.74';

$Apache::AuthzDBI::DEBUG = 0;


my %Config = (
    'Auth_DBI_data_source'    => '',
    'Auth_DBI_username'       => '',
    'Auth_DBI_password'       => '',
    'Auth_DBI_grp_table'      => '',
    'Auth_DBI_uid_field'      => '',
    'Auth_DBI_grp_field'      => '',
    'Auth_DBI_authoritative'  => 'on',
);

sub handler {

    my ($r) = @_;
    my ($i, $key, $val);

    my ($prefix) = "$$ Apache::AuthzDBI";

    if ( $Apache::AuthzDBI::DEBUG ) {
        my ($type) = '';
        $type .= 'initial ' if $r->is_initial_req;
        $type .= 'main'     if $r->is_main;
        print STDERR "\n==========\n$prefix request type = $type\n";
    }

    return OK unless $r->is_initial_req; # only the first internal request

    print STDERR "REQUEST:\n", $r->as_string if $Apache::AuthzDBI::DEBUG;

    my ($user_result)  = DECLINED;
    my ($group_result) = DECLINED;

    my ($user_sent) = $r->connection->user;
    print STDERR "$prefix user sent = >$user_sent<\n" if $Apache::AuthzDBI::DEBUG;

    # get configuration
    my $attr = { };
    while(($key, $val) = each %Config) {
        $val = $r->dir_config($key) || $val;
        $key =~ s/^Auth_DBI_//;
        $attr->{$key} = $val;
        printf STDERR "$prefix Config{ %-15s } = %s\n", $key, $val if $Apache::AuthzDBI::DEBUG;
    }

    # if not configured decline
    unless ( $attr->{grp_table} && $attr->{uid_field} && $attr->{grp_field} ) {
        printf STDERR "$prefix not configured, return DECLINED\n" if $Apache::AuthzDBI::DEBUG;
        return DECLINED;
    }

    # check requirements
    my ($ary_ref) = $r->requires;
    unless ( $ary_ref ) {
        if ( $attr->{authoritative} eq 'on' ) {
            $r->log_reason("user $user_sent denied, no access rules specified (DBI-Authoritative)", $r->uri);
            $r->note_basic_auth_failure;
            return AUTH_REQUIRED;
        }
        printf STDERR "$prefix no requirements and not authoritative, return DECLINED\n" if $Apache::AuthzDBI::DEBUG;
        return DECLINED;
    }

    # iterate over all requirement directives
    my($hash_ref, @require);
    foreach $hash_ref (@$ary_ref) {
        while (($key,$val) = each %$hash_ref) {
            last if $key eq 'requirement';
        }
        print STDERR "$prefix requirement: $val\n" if $Apache::AuthzDBI::DEBUG;
        $val =~ s/^\s*require\s+//;
        @require = split /\s+/, $val;

        # check for user
        if ( $user_result != OK && $require[0] eq 'user' ) {
            $user_result = AUTH_REQUIRED;
            for ($i = 1; $i <= $#require; $i++ ) {
                if ( $require[$i] eq $user_sent ) {
                    print STDERR "$prefix user_result = OK: $require[$i] = $user_sent\n" if $Apache::AuthzDBI::DEBUG;
                    $user_result = OK;
                    last;
               }
            }
            if ( $attr->{authoritative} eq 'on' && $user_result != OK ) {
                $r->log_reason("User $user_sent not found, (DBI-Authoritative)", $r->uri);
                $r->note_basic_auth_failure;
                return AUTH_REQUIRED;
            }
        }

        # check for group
        if ( $group_result != OK && $require[0] eq 'group' ) {
            $group_result = AUTH_REQUIRED;

            unless ( $attr->{data_source} ) {
                $r->log_reason("missing source parameter for database connect", $r->uri);
                return SERVER_ERROR;
            }

            # connect to database
            my $dbh;
            unless ($dbh = DBI->connect($attr->{data_source}, $attr->{username}, $attr->{password})) {
                $r->log_reason("db connect error with $attr->{data_source}", $r->uri);
                return SERVER_ERROR;
            }

            $user_sent = $dbh->quote($user_sent);

            for ($i = 1; $i <= $#require; $i++ ) {

                my ($group) = $dbh->quote($require[$i]);

                my $statement = "SELECT $attr->{grp_field} FROM $attr->{grp_table} WHERE $attr->{uid_field}=$user_sent AND $attr->{grp_field}=$group";
                print STDERR "$prefix statement = $statement\n" if $Apache::AuthzDBI::DEBUG;

                # prepare statement
                my $sth;
                unless ($sth = $dbh->prepare($statement)) {
                    $r->log_reason("can not prepare statement: $DBI::errstr", $r->uri);
                    return SERVER_ERROR;
                }

                # execute statement
                my $rv;
                unless ($rv = $sth->execute) {
                    $r->log_reason("can not execute statement: $DBI::errstr", $r->uri);
                    return SERVER_ERROR;
                }

                # fetch result
                $group = $sth->fetchrow_array;
                print STDERR "$prefix group = >$group<\n" if $Apache::AuthzDBI::DEBUG;

                $sth->finish;

                # check group
                if ( $require[$i] eq $group ) {
                    $group_result = OK;
                    print STDERR "$prefix group_result = OK: $require[$i] = $group\n" if $Apache::AuthzDBI::DEBUG;
                    last;
                }
	    }

            $dbh->disconnect;

            if ( $attr->{authoritative} eq 'on' && $group_result != OK ) {
                $r->log_reason("user $user_sent not in right groups, (DBI-Authoritative)", $r->uri);
                $r->note_basic_auth_failure;
                return AUTH_REQUIRED;
            }
        }

        # check for valid-user
        if ( $require[0] eq 'valid-user' ) {
            $user_result = OK;
            print STDERR "$prefix user_result = OK: valid-user\n" if $Apache::AuthzDBI::DEBUG;
        }
    }

    if ( $attr->{authoritative} eq 'on' &&
        ($group_result == AUTH_REQUIRED || $user_result == AUTH_REQUIRED) ) {
        my ($reason) = $group_result == AUTH_REQUIRED ? 'USER' : 'GROUP';
	$r->log_reason("DBI-Authoritative: Access denied on $reason rule(s)", $r->uri);
	return AUTH_REQUIRED;
    }

    if ( $user_result == OK || $group_result == OK ) {
        printf STDERR "$prefix return OK\n" if $Apache::AuthzDBI::DEBUG;
	return OK;
    }

    printf STDERR "$prefix fall through, return DECLINED\n" if $Apache::AuthzDBI::DEBUG;
    return DECLINED;
}


1;

__END__


=head1 NAME

Apache::AuthzDBI - Authorization via Perl's DBI


=head1 SYNOPSIS

 # Configuration in httpd.conf or srm.conf:

 PerlModule Apache::AuthzDBI

 # Authorization in .htaccess:

 AuthName DBI
 AuthType Basic

 #authorize via DBI
 PerlAuthzHandler Apache::AuthzDBI

 PerlSetVar Auth_DBI_data_source   dbi:driver:dsn
 PerlSetVar Auth_DBI_username      db_username
 PerlSetVar Auth_DBI_password      db_password
 #DBI->connect($data_source, $username, $password)

 PerlSetVar Auth_DBI_grp_table     users
 PerlSetVar Auth_DBI_uid_field     username
 PerlSetVar Auth_DBI_grp_field     groupname
 #SELECT grp_field FROM grp_table WHERE uid_field=$user AND grp_field=$group

 <Limit GET>
 require user   user_1  user_2 ...
 require group group_1 group_2 ...
 </Limit>

The AuthType is limited to Basic. You may use one or more valid require 
lines. For a single require line with the tokens valid-user or with  
distinct user names it is sufficient to use only the AuthenDBI module. 


=head1 DESCRIPTION

This module allows authorization against a database using Perl's DBI. 
For supported DBI drivers see: 

 http://www.hermetica.com/technologia/DBI/

When the authorization handler is called, the authentication has already been 
done. This means, that the given username/password has been validated. 

The handler analyzes and processes the requirements line by line. The request 
is accepted only if all requirement lines are accepted. 

In case of one or more user-names, they are compared with the given user-name 
until the first match. If there is no match and the authoritative directive 
is set to 'on' the request is rejected. 

In case of one or more group-names, for every group the given user is looked 
up in the database with the constraint, that the user must be a member of this 
group. If there is no match and the authoritative directive is set to 'on' the 
request is rejected. 

In case of 'valid-user' the request is accepted. 


=head1 LIST OF TOKENS

=item *
Auth_DBI_data_source

The data_source value should begin with 'dbi:driver_name:'. This value (with 
the 'dbi:...:' prefix removed) is passed to the database driver for processing 
during connect. 

=item *
Auth_DBI_username

The username argument is passed to the database driver for processing during 
connect.

=item *
Auth_DBI_password

The password argument is passed to the database driver for processing during 
connect.

=item *
Auth_DBI_grp_table

Contains at least the fields with the username and the groupname. 

=item *
Auth_DBI_uid_field

Field-name containing the username in the Auth_DBI_grp_table. 

=item *
Auth_DBI_grp_field

Field-name containing the groupname in the Auth_DBI_grp_table. 

=item *
Auth_DBI_authoritative  < on / off>

Default is 'on'. When set 'on', there is no fall-through to other 
authorization methods if the authorization check fails. When this directive 
is set to 'off', control is passed on to any other authorization modules. Be 
sure you know what you are doing when you decide to switch it off. 


=head1 CONFIGURATION

The module should be loaded upon startup of the Apache daemon. 
It needs the AuthenDBI module for the authentication part. 
Add the following lines to your httpd.conf or srm.conf:

 PerlModule Apache::AuthenDBI
 PerlModule Apache::AuthzDBI


=head1 PREREQUISITES

For AuthzDBI you need to enable the appropriate call-back hooks when making 
mod_perl: 

  perl Makefile.PL PERL_AUTHEN=1 PERL_AUTHZ=1. 


=head1 SEE ALSO

L<Apache>, L<mod_perl>, L<DBI>


=head1 AUTHORS

=item *
mod_perl by Doug MacEachern <dougm@osf.org>

=item *
DBI by Tim Bunce <Tim.Bunce@ig.co.uk>

=item *
Apache::AuthzDBI by Edmund Mergl <E.Mergl@bawue.de>


=head1 COPYRIGHT

The Apache::AuthzDBI module is free software; you can redistribute it and/or
modify it under the same terms as Perl itself.

=cut
