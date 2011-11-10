#!/usr/bin/perl
use IO::Socket;
use DBI;
use DBD::Pg;
use DBD::ODBC;
use Net::IP;

close(STDIN);
close(STDOUT);
close(STDERR);
exit if (fork());
exit if (fork());

# Variables and Constants
my $MAXLEN = 1524;
my ($lsec,$lmin,$lhour,$lmday,$lmon,$lyear,$lwday,$lyday,$lisdst)=localtime(time); $lyear+=1900; $lmon+=1;
@fact=("kernel","user","mail","system","security","internal","printer","news","uucp","clock","security2",
"FTP","NTP","audit","alert","clock2","local0","local1","local2","local3","local4","local5","local6","local7");
my $perhost=0;        # Each source gets its own log file
my $daily=0;          # Create daily log files (date in file name)
my $perfacility=0;    # Each facility gets its own log file
mkdir("log");         # Create log directory if it does not exist yet

#my $dbhost = 'localhost';
#my $dbname = 'haproxy_performance';

my $dbname = 'haproxy_performance';

#my $dbh = DBI->connect("dbi:Pg:dbname=$dbname",'','',{AutoCommit => 0});
my $dbh = DBI->connect('dbi:ODBC:SqlDev',"haproxyrequestlog","haproxyrequestlog",{AutoCommit => 0});


my $sth = $dbh->prepare(
	"INSERT INTO perflog(
	pid, client_ip, client_port, datestamp, frontend_name, backend_name, 
	server_name, tq, tw, tc, tr, tt, status_code, bytes_read, actconn, 
	feconn, beconn, srv_conn, retries, srv_queue, backend_queue, host_header,
	http_verb, http_uri, http_version)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);");


# Start Listening on UDP port 514
$sock = IO::Socket::INET->new(LocalPort => '5140', Proto => 'udp')||die("Socket: $@");
my $rin = '';
my $buf;
do{
  $sock->recv($buf, $MAXLEN);
  my ($port, $ipaddr) = sockaddr_in($sock->peername);
  my $hn = gethostbyaddr($ipaddr, AF_INET);
  $buf=~/<(\d+)>(.*?):(.*)/;
  my $pri=$1;
  my $head=$2;
  my $msg=$3;
  my $sev=$pri % 8;
  my $fac=($pri-$sev) / 8;
  logsys($fac,$sev,$head,$msg,$hn);
}while(1);

# Logs Syslog messages
sub logsys{
  my $fac=shift; my $sev=shift; my $head=shift; my $msg=shift; my $hn=shift;
  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime(time); $year+=1900; $mon++;
  my $pf=""; my $fn=""; my $facdiff="";
  if ($perfacility){$facdiff="-".$fact[$fac];}
  if ($daily){$facdiff.=sprintf "-%04d-%02d-%02d", $year, $mon, $mday;}
  if ($perhost){mkdir("log\\$hn"); $fn=$hn . "\\syslog".$facdiff.".log"; $pf=$hn ."\\";}else{$fn="syslog".$facdiff.".log";}
  my $p=sprintf "[%02d.%02d.%04d, %02d:%02d:%02d, %1d, %1d] %s\n", $mday, $mon, $year, $hour, $min, $sec, $fac, $sev, $msg;
  print "$msg\n";
  if ($msg =~ /([\d:]*) haproxy\[(\d*)\]: (\b(?:\d{1,3}\.){3}\d{1,3}\b):(\d*) \[(.*)\] (.*) (.*)\/(.*) (\d*)\/(\d*)\/(\d*)\/(\d*)\/(\d*) (\d*) (\d*) (.*) (.*) (.*) (\d*)\/(\d*)\/(\d*)\/(\d*)\/(\d*) (\d*)\/(\d*) \{(.*)\} \"(.*) (.*) (.*)\"/ ) {
	  my $ip = new Net::IP("$3");
	  my $intip = $ip->intip();
	  my $date = join(" ",split(':',$5,2));
	  
	  $sth->bind_param(1,$2);
	  $sth->bind_param(2,$intip->bstr());
	  $sth->bind_param(3,$4);
	  $sth->bind_param(4,$date);
	  $sth->bind_param(5,$6);
	  $sth->bind_param(6,$7);
	  $sth->bind_param(7,$8);
	  $sth->bind_param(8,$9);
	  $sth->bind_param(9,$10);
	  $sth->bind_param(10,$11);
	  $sth->bind_param(11,$12);
	  $sth->bind_param(12,$13);
	  $sth->bind_param(13,$14);
	  $sth->bind_param(14,$15);
	  $sth->bind_param(15,$19);
	  $sth->bind_param(16,$20);
	  $sth->bind_param(17,$21);
	  $sth->bind_param(18,$22);
	  $sth->bind_param(19,$23);
	  $sth->bind_param(20,$24);
	  $sth->bind_param(21,$25);
	  $sth->bind_param(22,$26);
	  $sth->bind_param(23,$27);
	  $sth->bind_param(24,$28);
	  $sth->bind_param(25,$29);
	  my $rv = $sth->execute();
	  $dbh->commit();
  } else {
	  print STDERR "\nDROPPED: $msg\n\n";
  }

}
