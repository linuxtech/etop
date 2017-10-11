#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent ();
use JSON::Parse 'parse_json';
use Data::Dumper;
use Curses;
use POSIX qw(strftime);
use utf8;

my $ARG = {};
foreach (@ARGV){
        my ($key, $value) = split /\=/;
        $ARG->{$key} = $value;
}

my $WANT_VAL = { 'search_q' => 1 };
map({$WANT_VAL->{$_} = 1} split($ARG->{get}));

my $ua = LWP::UserAgent->new;
$ua->timeout(10);

my $SRVINFO;
my $VALUES = {
        'search_q' => '$SRVINFO->{nodes}->{$srv}->{indices}->{search}->{query_total}',
        'hostname' => '$SRVINFO->{nodes}->{$srv}->{name}',
        'doc_total'=> '$SRVINFO->{nodes}->{$srv}->{indices}->{docs}->{count}'
                };

my $win = Curses->new(); 
noecho(); 
$win->getmaxyx(my $row, my $col);
          
my $prev = {};
while(1){
        my $timestamp = strftime "%Y-%m-%d %H:%M:%S", localtime;
        $win->addstr(0, $col-20, $timestamp);
        my $response = $ua->get($ARG->{api});
        if ($response->is_success) {
            $SRVINFO = parse_json($response->decoded_content);
        }
        else {
             die $response->status_line;
        }
        
        my $row=1;
        foreach my $srv (sort keys %{$SRVINFO->{nodes}}){
                my $output = eval($VALUES->{hostname});
                $output .= ' | ';
                foreach my $name (sort keys %{$VALUES}){
                        if(defined $WANT_VAL->{$name}){
                                my $value = eval($VALUES->{$name});
                                my $delta = defined $prev->{$srv}->{$name} ? $value - $prev->{$srv}->{$name} : 0;
                                $output .= "$name:$value Δ:$delta | ";
                                $prev->{$srv}->{$name} = $value;
                        }
                }

                $win->addstr($row,0, "$output\n");
                $row +=1;
        }
        $win->refresh();
        sleep(5);
}

END:
endwin();

