#!/usr/bin/env perl
# To speed up processing of large files, GNU parallel can be used:
#   $ parallel --pipe -k json-format.pl INPUT
use strict;
use warnings;
use Term::ANSIColor;
use Getopt::Long;

my $reset = color('reset');
my %format = (
  FIELD  => color('bold'),
  NULL   => color('cyan'),
  BOOL   => color('red'),
  NUMBER => color('magenta'),
  STRING => color('blue'),
  ERROR  => color('bold white on_red'),
);

my ($color, $keep_ws, $help) = 'auto';
if (!GetOptions('color=s' => \$color, 'keep-ws' => \$keep_ws, 'help' => \$help)
  || $help) {
  print STDERR
    "Usage: $0 [OPTION...] [FILE...]\n" .
    "Pretty-print and colorify JSON\n" .
    "\n" .
    "  --help         print this help\n" .
    "  --keep-ws      retain all original whitespace\n" .
    "  --color=COLOR  'always', 'never' or 'auto' (the default)\n";
  exit 2;
}

%format = ()
  if $color eq 'never' || $color eq 'auto' && !-t STDOUT;

# Hash lookup is the fastest way to qualify tokens, however it cannot be used
# for everything and we need to fall back to regular expressions
my %lookup = (
  '[' => 'LBRACKET', '{' => 'LBRACE',
  ']' => 'RBRACKET', '}' => 'RBRACE',
  ':' => 'COLON', ',' => 'COMMA',
  'true' => 'BOOL', 'false' => 'BOOL', 'null' => 'NULL',
);
my @pats = (
  ['"(?:[^\\\\"]*|\\\\(?:u[\da-f]{4}|["\\\\/bfnrt]))*"' => 'STRING'],
  ['-?\d+(?:\.\d+)?(?:[eE][-+]?\d+)?' => 'NUMBER'],
  ['[ \t\r\n]+' => 'WS'],
);
my @tokens = map {[qr/^$_->[0]$/s, $_->[1]]} @pats;

# m//g is the fastest way to explode text into tokens in the first place
# and we need to construct an all-encompassing regular expression for it
my @all_pats = map {$_->[0]} @pats;
push @all_pats, quotemeta for keys %lookup;
my $any_token = qr/\G(${\join '|', @all_pats})/;

# FIXME: this probably shouldn't be a global variable
my $indent = 0;

sub nexttoken ($) {
  my $json = shift;
  if (!@$json) {
    return unless defined (my $line = <>);
    push @$json, $line =~ /$any_token/gsc;
    push @$json, substr $line, pos $line
      if pos $line != length $line;
  }

  my $text = shift @$json;
  if (my $s = $lookup{$text}) {
    return $s, $text;
  }
  for my $s (@tokens) {
    return $s->[1], $text if $text =~ $s->[0];
  }
  return 'ERROR', $text;
}

sub skip_ws ($) {
  my $json = shift;
  while (my ($token, $text) = nexttoken $json) {
    next if !$keep_ws && $token eq 'WS';
    return $token, $text;
  }
  return;
}

sub printindent () {
  print "\n";
  print '  ' x $indent;
}

sub do_value ($$$);
sub do_object ($) {
  my $json = shift;
  my $in_field_name = 1;
  my $first = 1;
  while (my ($token, $text) = skip_ws $json) {
    if ($token eq 'COLON') {
      $in_field_name = 0;
    } elsif ($token eq 'COMMA') {
      $in_field_name = 1;
    } elsif ($token eq 'STRING') {
      $token = 'FIELD' if $in_field_name;
    }
    if ($token eq 'RBRACE') {
      $indent--;
      printindent unless $keep_ws;
    } elsif ($first) {
      printindent unless $keep_ws;
      $first = 0;
    }
    do_value $token, $text, $json;
    return if $token eq 'RBRACE';
  }
}

sub do_array ($) {
  my $json = shift;
  my $first = 1;
  while (my ($token, $text) = skip_ws $json) {
    if ($token eq 'RBRACKET') {
      $indent--;
      printindent unless $keep_ws;
    } elsif ($first) {
      printindent unless $keep_ws;
      $first = 0;
    }
    do_value $token, $text, $json;
    return if $token eq 'RBRACKET';
  }
}

sub do_value ($$$) {
  my ($token, $text, $json) = @_;
  if (my $format = $format{$token}) {
    print $format, $text, $reset;
  } else {
    print $text;
  }
  if ($token eq 'LBRACE') {
    $indent++;
    do_object $json;
  } elsif ($token eq 'LBRACKET') {
    $indent++;
    do_array $json;
  } elsif ($token eq 'COMMA') {
    printindent unless $keep_ws;
  } elsif ($token eq 'COLON') {
    print ' ' unless $keep_ws;
  }
}

my @buffer;
while (my ($token, $text) = skip_ws \@buffer) {
  do_value $token, $text, \@buffer;
}
print "\n" unless $keep_ws;
