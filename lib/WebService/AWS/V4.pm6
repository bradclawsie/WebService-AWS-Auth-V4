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

use Digest::SHA;
use URI;
use URI::Escape;

# perhaps right way to do this is to just have a constructor that takes a URI, headers, and body

class X::WebService::AWS::V4::ParseError is Exception is export {
    has $.input;
    has $.err;
    method message() { "With $.input, parse error: $.err" }
}

class X::WebService::AWS::V4::MethodError is Exception is export {
    has $.input;
    method messae() { "With $.input, missing http method. Only GET POST HEAD are supported"; }
}

# These are the methods that can be used with AWS services.
our $Methods = set < GET POST HEAD >; 

class WebService::AWS::V4 is export {

    has Str $.method is required;
    has Str @.headers is required;
    has Str $.body is required;
    has Str $.uri is required;
    has URI $!uri_obj;
    has Str %!header_map;
    
    submethod BUILD(Str:D :$method,Str:D :@headers,Str:D :$body, Str:D :$uri) {

        # Make sure the method passed is allowed
        unless $method (elem) $Methods {
            X::WebService::AWS::V4::MethodError(input => $method).throw;
        }
        $!method := $method;

        # Map the lowercased and trimmed header names to trimmed header values. Will throw
        # an exception if there is an error, let caller catch it.
        %!header_map = &map_headers(@headers);

        $!body := $body;

        # Now create a URI obj from the URI string and make sure that the method and host are set.
    }

    my sub map_headers(Str:D @headers) returns Hash:D {
        my %header_map = ();
        for @headers -> $header {
            if $header ~~ /^(\S+)\:(.*)$/ {
                my ($k,$v) = ($0,$1);
                $v = $v.trim;
                if $v !~~ /\"/ {
                    $v ~~ s:g/\s+/ /;
                } 
                %header_map{$k.lc.trim} = $v;
            } else {
                X::WebService::AWS::V4::ParseError.new(input => $header,err => 'cannot parse header').throw;
            }
        }
        unless %header_map{'host'}:exists {
            X::WebService::AWS::V4::ParseError.new(input => @headers.join("\n"),err => 'host header required').throw;
        }
        return %header_map;
    }

}

sub awsv4_canonicalize_uri(URI:D $uri) returns Str:D is export {
    my Str $path = $uri.path;
    return '/' if $path.chars == 0 || $path eq '/';
    return uri_escape($path);
}

sub awsv4_canonicalize_query(URI:D $uri) returns Str:D is export {
    my Str $query = $uri.query;
    return '' if $query.chars == 0;
    my Str @pairs = $query.split('&');
    my Str @escaped_pairs = ();
    for @pairs -> $pair {
        if $pair ~~ /^(\S+)\=(\S*)$/ {
            my ($k,$v) = ($0,$1);
            push(@escaped_pairs,uri_escape($k) ~ '=' ~ uri_escape($v));
        } else {
            X::WebService::AWS::V4::ParseError.new(input => $pair,err => 'cannot parse query key=value').throw;
        }            
    }
    return @escaped_pairs.sort().join('&');
}

sub map_headers(Str:D @headers) returns Hash:D is export {
    my %header_map = ();
    for @headers -> $header {
        if $header ~~ /^(\S+)\:(.*)$/ {
            my ($k,$v) = ($0,$1);
            $v = $v.trim;
            if $v !~~ /\"/ {
                $v ~~ s:g/\s+/ /;
            } 
            %header_map{$k.lc.trim} = $v;
        } else {
            X::WebService::AWS::V4::ParseError.new(input => $header,err => 'cannot parse header').throw;
        }
    }
    unless %header_map{'host'}:exists {
        X::WebService::AWS::V4::ParseError.new(input => @headers.join("\n"),err => 'host header required').throw;
    }
    return %header_map;
}

sub awsv4_canonicalize_headers(%h) returns Str:D is export {
    return %h.keys.sort.map( -> $k { $k ~ ':' ~ %h{$k}} ).join("\n") ~ "\n";
}

sub awsv4_signed_headers(%h) returns Str:D is export {
    return %h.keys.sort.join(';') ~ "\n";
}

sub sha256_base16(Str:D $s) returns Str:D {
    my $sha256 = sha256 $s.encode: 'ascii';
    return [~] $sha256.list».fmt: "%02x";
}
