package Apache::DBI;

use Apache ();
use Apache::Constants qw(OK AUTH_REQUIRED DECLINED SERVER_ERROR);
use DBI ();
use strict;

my $VERSION = '0.2';

my $DEBUG = 0;

my (%Connected);

sub connect {

    my($self, @args) = @_;
    my $idx = join (":", (@args));
    my $buf = '';

    return $Connected{$idx} if $Connected{$idx};
    print STDERR "Pid = $$, Apache::DBI::connect to '$idx'\n" if $DEBUG;
    $Connected{$idx} = DBI->connect(@args);

}


sub disconnect {

    my($dbh) = @_;
    my($key, $value);

    while (($key,$value) = each %Connected) {
	last if $value == $dbh;
    }

    if ($value == $dbh) {
        print STDERR "Pid = $$, Apache::DBI::disconnect of '$key'\n" if $DEBUG;
        $value->disconnect;
    } else {
        print STDERR "Pid = $$, Apache::DBI::disconnect: couldn't find database handle !\n";
    }
}


my %Config = (
    'AuthDBIUser'          => '',
    'AuthDBIAuth'          => '',
    'AuthDBIDB'            => '',
    'AuthDBIDriver'        => '',
    'AuthDBINameField'     => '',
    'AuthDBIPasswordField' => '',
    'AuthDBIUserTable'     => '',
);

sub handler {

    my($r) = @_;

    print STDERR "\nApache::DBI::handler\n" if $DEBUG;

    # here the dialog pops up and asks you for userid and password
    my($res, $passwd_sent) = $r->get_basic_auth_pw;
    print STDERR "get_basic_auth = $res, password sent = $passwd_sent\n" if $DEBUG;
    return $res if $res; # return on first internal request (res = 401)

    my($key, $val);
    my $attr = { };
    while(($key, $val) = each %Config) {
	$val = $r->dir_config($key) || $val;
	$key =~ s/^AuthDBI//;
	$attr->{$key} = $val;
        printf STDERR "Config{ %-15s } = %s\n", $key, $val if $DEBUG;
    }

    my $dbh;
    unless ($dbh = Apache::DBI->connect($attr->{DB}, $attr->{User}, $attr->{Auth}, $attr->{Driver})) {
	$r->log_reason("db connect error with $attr->{DB}", $r->uri);
	$r->note_basic_auth_failure;
	return SERVER_ERROR;
    }

    my $user_sent = $r->connection->user;
    print STDERR "user sent = $user_sent \n" if $DEBUG;

    my $statement = "SELECT $attr->{PasswordField} from $attr->{UserTable} WHERE $attr->{NameField}='$user_sent'";
    print STDERR "statement = $statement" if $DEBUG;

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
	$r->log_reason("User '$user_sent' not found", $r->uri);
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    unless (crypt($passwd_sent, $passwd) eq $passwd) {
	$r->log_reason("user '$user_sent': password mismatch", $r->uri);
	$r->note_basic_auth_failure;
	return AUTH_REQUIRED;
    }

    return OK;
}


Apache::Status->menu_item(

    'DBI' => 'DBI connections',
    sub {
        my($r, $q) = @_;
        my(@s) = qw(<TABLE><TR><TD>Database</TD><TD>Username</TD><TD>Driver</TD></TR>);
        for (keys %Connected) {
            push @s, '<TR><TD>', join('</TD><TD>', (split(':', $_))[0,1,3]), "</TD></TR>\n";
        }
        push @s, '</TABLE>';
        return \@s;
   }

) if Apache->module('Apache::Status');


1;

__END__

=head1 NAME

Apache::DBI - Authenticate via Perl's DBI using a persistent database connection

=head1 SYNOPSIS

 # Configuration in httpd.conf or srm.conf

 PerlModule Apache::DBI

 # Authentication in .htaccess

 AuthName DBI
 AuthType Basic

 #authenticate via DBI
 PerlAuthenHandler Apache::DBI

 PerlSetVar AuthDBIDB     dbname
 PerlSetVar AuthDBIUser   username
 PerlSetVar AuthDBIAuth   auth
 PerlSetVar AuthDBIDriver driver
 #DBI->connect(qw(AuthDBIDB AuthDBIUser AuthDBIAuth AuthDBIDriver))

 PerlSetVar AuthDBIUserTable table
 PerlSetVar AuthDBINameField user
 PerlSetVar AuthDBIPasswordField password

 <Limit GET POST>
 require valid-user
 </Limit>

The require directive is limited to 'valid-user' and 'user xxx' (no group 
support). 

 # Persistent database connection in CGI script

 use Apache::DBI;

 $dbh = Apache::DBI->connect(...);

=head1 DESCRIPTION

This module consists out of two parts which can be used 
independently:

it allows the apache server to authenticate against a database 
and it provides a persistent database connection. 

The authentication initiates a persistent database conection, 
but the persistent database connection can also be used without 
authentication. 

The database access uses Perl's DBI. For supported DBI drivers see: 

 http://www.hermetica.com/technologia/DBI/

For using the persistent database connection all you really need is 
to replace DBI with Apache::DBI. When connecting to a database the 
module looks if a database handle from a previous connect request is 
already stored. If not, a new connection is established and the handle 
is stored for later re-use. There is no need to delete the disconnect
statements from your code. They won't do anything. If you want to do an 
explicit disconnect you need to call: Apache::DBI::disconnect($dbh).

The Apache::DBI module still has a limitation: it keeps database 
connections persistent on a per process basis. The problem is, if 
a user accesses several times a database during one session, the http 
requests will be handled very likely by different httpd children. Every 
child process needs to do its own connect. It would be nice, if all httpd 
children could share the database handles. I still don't know how to solve 
this problem. So if anyone knows how to do this, please let me know. 

This module plugs in a menu item for Apache::Status. The menu lists 
the current database connections. It should be considered incomplete 
because of the limitations explained above. It shows the current database 
connections for one specific httpd process, the one which happens to 
serve the current request. Other httpd children might have other 
database connections. 


=head1 SEE ALSO

Apache(3), DBI(3)

=head1 AUTHORS

The authentication part is taken from Apache::AuthenDBI and rewritten, 
so that it does not depend anymore on HTTPD.

 mod_perl by Doug MacEachern <dougm@osf.org>
 DBI by Tim Bunce <Tim.Bunce@ig.co.uk>
 Apache::DBI by Edmund Mergl <E.Mergl@bawue.de>
