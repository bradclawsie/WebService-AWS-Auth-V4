use v6;

=begin pod

=head1 NAME

WebService::AWS::V4 - A Perl6 implementation of AWS v4 authentication methods.

=head1 DESCRIPTION

=head1 SYNOPSIS

=head1 AUTHOR

Brad Clawsie (PAUSE:bradclawsie, email:brad@b7j0c.org)

=head1 LICENSE

This module is licensed under the BSD license, see:

https://b7j0c.org/stuff/license.txt

=end pod

unit module WebService::AWS::V4:auth<bradclawsie>:ver<0.0.1>;

use URI;
use URI::Escape;

my sub canonicalize_uri(URI:D $uri) returns Str:D {
    my Str $path = $uri.path;
    return '/' if $path.chars == 0;
    return uri_escape($path);
}

multi awsv4_canonicalize_uri(Str:D $uri_str) returns Str:D is export {
    return canonicalize_uri(URI.new($uri_str));
}

multi awsv4_canonicalize_uri(URI:D $uri) returns Str:D is export {
    return canonicalize_uri($uri);
}

