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
our constant $Methods = set < GET POST HEAD >; 

our constant $HMAC_name = 'AWS4-HMAC-SHA256';

class WebService::AWS::V4 {

    has Str $.method is required;
    has Str @.headers is required;
    has Str $.body is required;
    has URI $!uri;
    has Str %!header_map;
    
    submethod BUILD(Str:D :$method,Str:D :@headers,Str:D :$body, Str:D :$uri) {

        # Make sure the method passed is allowed
        unless $method (elem) $Methods {
            X::WebService::AWS::V4::MethodError(input => $method).throw;
        }
        $!method := $method;

        @!headers = @headers;
        
        # Map the lowercased and trimmed header names to trimmed header values. Will throw
        # an exception if there is an error, let caller catch it.
        %!header_map = &map_headers(@headers);

        $!body := $body;

        # Now create a URI obj from the URI string and make sure that the method and host are set.
        $!uri = URI.new(:$uri);
        unless $!uri.scheme ne '' && $!uri.host ne '' {
            X::WebService::AWS::V4::ParseError.new(input => :$uri,err => 'cannot parse uri').throw;
        }
    }

    my sub map_headers(Str:D @headers) returns Hash:D {
        my %header_map = ();
        for @headers -> $header {
            if $header ~~ /^(\S+)\:(.*)$/ {
                my ($k,$v) = ($0,$1);
                $v = $v.trim;
                if $v !~~ / '"' / {
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

    # Get the SHA256 for a given string.
    our sub sha256_base16(Str:D $s) returns Str:D is export {
        my $sha256 = sha256 $s.encode: 'ascii';
        [~] $sha256.list».fmt: "%02x";
    }

    # Use this as a 'formatter' method for a DateTime object to get the X-Amz-Date format.
    our sub amz_date_formatter(DateTime:D $dt) returns Str:D is export {
        sprintf "%04d%02d%02dT%02d%02d%02dZ",
        $dt.utc.year,
        $dt.utc.month,
        $dt.utc.day,
        $dt.utc.hour,
        $dt.utc.minute,
        $dt.utc.second;        
    }

    # STEP 1 CANONICAL REQUEST
    
    method canonical_uri() returns Str:D {
        my Str $path = $!uri.path;
        return '/' if $path.chars == 0 || $path eq '/';
        return uri_escape($path);
    }

    method canonical_query() returns Str:D {
        my Str $query = $!uri.query;
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

    method canonical_headers() returns Str:D {
        my %h := %!header_map;
        %h.keys.sort.map( -> $k { $k ~ ':' ~ %h{$k}} ).join("\n") ~ "\n";
    }
    
    method signed_headers() returns Str:D {
        my %h := %!header_map;
        %h.keys.sort.join(';');
    }
    
    method canonical_request() is export {
        ($!method,
         self.canonical_uri(),
         self.canonical_query(),
         self.canonical_headers(),
         self.signed_headers(),
         &sha256_base16($!body)).join("\n");
    }
    
    # STEP 2 STRING TO SIGN

    method string_to_sign() is export {
        
    }
}

