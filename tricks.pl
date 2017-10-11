#!/usr/bin/perl
use strict;
use warnings;
use Data::Dumper;

#=== use ARGV as hash ===
my $ARG = {};
foreach (@ARGV){
	my ($key, $value) = split /\=/;
	$ARG->{$key} = $value;
}
foreach (keys %{$ARG}){
	print "$_ => $ARG->{$_}\n";
}
#===                 ===

#eval {
#	local $SIG{ALRM} = sub {MAINLOOP();}
#}





