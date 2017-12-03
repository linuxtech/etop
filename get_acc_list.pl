#!/usr/bin/perl

#System accounts checker
#PCI DSS

use strict;
use warnings;
use utf8;
my ($PW, $SH, $GR, %PASSWD, %SHADOW, %GROUP, %UID, %UID_NAME, %GID, %GID_NAME, %CHECK);

my @PASSWD_FORMAT = ('user','pass','uid','gid','info','home','shell');
my @SHADOW_FORMAT = ('user','pass','last_changed','changed_before','must_changed','exp_warn','expires_in','disabled_since','reserved');
my @GROUP_FORMAT = ('group','pass','gid','members');

open $PW, '<', '/etc/passwd' or die('Can not open /etc/passwd');
open $SH, '<', '/etc/shadow' or die('Can not open /etc/passwd');
open $GR, '<', '/etc/group' or die('Can not open /etc/passwd');

foreach (<$PW>) {
	chomp;
	my %record;
	@record{@PASSWD_FORMAT} = split /:/;
	$PASSWD{$record{'user'}} = \%record;

#Ensure no duplicate user names exist
	if(defined $UID_NAME{$record{'user'}}){print "Duplicate user name: $record{'user'}\n"}
	else {$UID_NAME{$record{'user'}}=1};

#Ensure no duplicate UIDs exist
	if(defined $UID{$record{'uid'}}){print "Duplicate UID: $record{'uid'}\n"}
	else {$UID{$record{'uid'}}=1};
} 

foreach (<$SH>) {
	chomp;
	my %record;
	@record{@SHADOW_FORMAT} = split /:/;
	$SHADOW{$record{'user'}} = \%record;
}

foreach (<$GR>) {
	chomp;
	my %record;
	@record{@GROUP_FORMAT} = split /:/;
	$GROUP{$record{'group'}} = \%record;

#Ensure no duplicate group names exist
	if(defined $GID_NAME{$record{'group'}}){print "Duplicate group name: $record{'group'}\n"}
	else {$GID_NAME{$record{'group'}}=1};
	
#Ensure no duplicate GIDs exist
	if(defined $GID{$record{'gid'}}){print "Duplicate GID: $record{'gid'}\n"}
	else {$GID{$record{'gid'}}=1};
}
close $PW;
close $SH;
close $GR;

my %checks;
@checks{@ARGV} = @ARGV;
if (defined $checks{'help'} || keys( %checks ) == 0){$CHECK{'help'}->{'func'}->()}
elsif (defined $checks{'all'}){$CHECK{'all'}->{'func'}->()}
else {
	foreach (sort keys %checks) {
		if(defined($CHECK{$_})){
			$CHECK{$_}->{'func'}->();
		} else {print "$_ check not implemented\n"; exit 1;}
	}
}

INIT {
###PCI DSS checks
	%CHECK = ( 
	'pass_empty' => {
		'description' => 'Ensure password fields are not empty',
		'func' => sub {
			foreach my $user (keys %SHADOW){
				if($SHADOW{$user}->{'pass'} eq ''){print "$user has empty password\n"}
			}
		}
	},
	'legacy_passwd' => {
		'description' => 'Ensure no legacy "+" entries exist in /etc/passwd',
		'func' => sub {
			foreach my $user (keys %PASSWD){
				if($user eq '+'){print "Legacy '+' entry exists in /etc/passwd\n"}
			}
		}				
	},
	'legacy_shadow' => {
		'description' => 'Ensure no legacy "+" entries exist in /etc/shadow',
		'func' => sub {
			foreach my $user (keys %SHADOW){
				if($user eq '+'){print "Legacy '+' entry exists in /etc/shadow\n"}
			}
		}
	},
	'legacy_group' => {
		'description' => 'Ensure no legacy "+" entries exist in /etc/group',
		'func' => sub {
			foreach my $group (keys %GROUP){
				if($group eq '+'){print "Legacy '+' entry exists in /etc/group\n"}
			}
		}
	},
	'root_uid' => {
		'description' => 'Ensure root is the only UID 0 account',
		'func'	=> sub {
			foreach my $user (keys %PASSWD){
				if($user ne 'root' && $PASSWD{$user}->{'uid'} eq '0'){print "Account $user has UID 0\n"}
			}
		}
	},
	'home_exists' => {
		'description' => 'Ensure all users home directories exist',
		'func' => sub {
			foreach my $user (keys %PASSWD){
				if($PASSWD{$user}->{'home'} eq ''){print "Home directory for user $user is not set\n"}
				elsif(! -d $PASSWD{$user}->{'home'}){print "Home directory for user $user does not exist\n"}
			}
		}
	},
	'forward_file' => {
		'description' => 'Ensure no users have .forward files',
		'func' => sub {
			foreach my $user (keys %PASSWD){
				if(-e "$PASSWD{$user}->{'home'}/.forward"){print "User $user has .forward file\n"}
			}
		}
	},
	'netrc_file' => {
		'description' => 'Ensure no users have .netrc files',
		'func' => sub {
			foreach my $user (keys %PASSWD){
		        	if(-e "$PASSWD{$user}->{'home'}/.netrc"){print "User $user has .netrc file\n"}
			}
		}
	},
	'rhosts_file' => {
		'description' => 'Ensure no users have .rhosts files',
		'func' => sub {
			foreach my $user (keys %PASSWD){
		        	if(-e "$PASSWD{$user}->{'home'}/.rhosts"){print "User $user has .rhosts file\n"}
			}
		}
	},
	'grp_consistency' => {
		'description' => 'Ensure all groups in /etc/passwd exist in /etc/group',
		'func' => sub {
			foreach my $user (keys %PASSWD){
				if(!defined($GID{$PASSWD{$user}->{'gid'}})){
					print "User $user has non-existent group number: $PASSWD{$user}->{'gid'}\n"
				}
			}
		}
	},
#Ensure users' home directories permissions are 750 or more restrictive
#Skipped
	'home_owners' => {
		'description' => 'Ensure users own their home directories',
		'func' => sub {
			foreach my $user (keys %PASSWD){
				if($PASSWD{$user}->{'uid'}>=500 && -d $PASSWD{$user}->{'home'}){
					my $owner = (getpwuid((stat $PASSWD{$user}->{'home'})[4]))[0];
					if($user ne $owner){print "Homedir of $user is owned by user '$owner'\n";}
				}
			}
		}
	},
	'shadow_empty' => {
		'description' => 'Ensure shadow group is empty',
		'func' => sub {
			if(defined $GROUP{'shadow'}->{'members'} && $GROUP{'shadow'}->{'members'} ne '' ){
				print "Group 'shadow' has members: $GROUP{'shadow'}->{'members'}\n"
			}
			foreach my $user (keys %PASSWD){
				if($PASSWD{$user}->{'gid'} == $GROUP{'shadow'}->{'gid'}){print "User $user is in group 'shadow'\n"}
			}
		}
	},
###Non PCI DSS checks
	'key_access' => {
		'description' => 'Ensure users don\'t have key-based access',
		'func' => sub {
			foreach my $user (keys %PASSWD){
				if( -s "$PASSWD{$user}->{'home'}/.ssh/authorized_keys"){
					print "User $user has non-empty authorized_keys file\n"
				}
			}
		}
	},
	'shell_users' => {
		'description' => 'List of users with shell access',
		'func' => sub {
			foreach my $user (keys %PASSWD){
				if(
					$PASSWD{$user}->{'shell'} ne '/usr/sbin/nologin' && 
					$PASSWD{$user}->{'shell'} ne '/sbin/nologin' &&
					$PASSWD{$user}->{'shell'} ne '/bin/false'
				){ 
					print "User $user has shell $PASSWD{$user}->{'shell'}\n"; 
				}
			}
		}
	},
	'all' => {
		'description' => "\tPerform all available checks",
		'func' => sub {
			foreach (sort keys %CHECK){
				next if($_ eq 'all' || $_ eq 'help');
				$CHECK{$_}->{'func'}->();
			}
		}
	},
	'help' => {
		'description' => "\tShow this help",
		'func' => sub {
			print "Performs a check of system settings compliance with the security requirements\n";
			print "Pick one or more arguments to execute checks.\n\n";
			foreach (sort keys %CHECK){
				print "$_\t\t$CHECK{$_}->{'description'}\n";
			}
		}
	}
)}
