#!/usr/bin/perl
use strict;
use warnings;
use LWP::UserAgent ();
use JSON::Parse 'parse_json';
use Data::Dumper;
use Curses;
use POSIX qw(strftime);

my $ua = LWP::UserAgent->new;
$ua->timeout(10);
# $ua->env_proxy;
my $SRVINFO;

my $win = Curses->new();
noecho();
$win->getmaxyx(my $row, my $col);

my $prev = {};
while(1){
        my $timestamp = strftime "%Y-%m-%d %H:%M:%S", localtime;
        $win->addstr(0, $col-20, $timestamp);
        my $response = $ua->get($ARGV[0]);
        if ($response->is_success) {
            $SRVINFO = parse_json($response->decoded_content);
        }
        else {
             die $response->status_line;
        }
          
        #print Dumper($SRVINFO);
        my $row=1;
        foreach my $srv (sort keys %{$SRVINFO->{nodes}}){
                my $search_query_total = $SRVINFO->{nodes}->{$srv}->{indices}->{search}->{query_total};
                my $delta = $search_query_total -$prev->{$srv}->{query_total};
                $win->addstr($row,0, "$SRVINFO->{nodes}->{$srv}->{name}: $SRVINFO->{nodes}->{$srv}->{indices}->{search}->{query_total}; delta: $delta\n");
                $prev->{$srv}->{query_total} = $search_query_total;
                $row +=1;
        }
        $win->refresh();
        sleep(5);
}   
    
END:
endwin();

