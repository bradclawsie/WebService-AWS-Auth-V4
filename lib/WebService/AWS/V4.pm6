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
use Digest::HMAC;
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

# HMAC algorithm.
our constant $HMAC_name      = 'AWS4-HMAC-SHA256';

# Signing version.
our constant $Auth_version   = 'AWS4';

# Host header normalized key.
our constant $Host_key       = 'host';

# X-Amz-Date header normalized key.
our constant $X_Amz_Date_key = 'x-amz-date';

# Termination string required in credential scope.
our constant $Termination_str = 'aws4_request';

class WebService::AWS::V4 {

    has Str $.method is required;
    has Str @.headers is required;
    has Str $.body is required;
    has Str $.region is required;
    has Str $.service is required;
    has Str $.secret is required;
    has URI $!uri;
    has Str %!header_map;
    has DateTime $!amz_date;
    
    submethod BUILD(Str:D :$method, :$body, :$uri, :$region, :$service, :$secret, :@headers){ 

        # Make sure the method passed is allowed
        unless $method (elem) $Methods {
            X::WebService::AWS::V4::MethodError(input => $method).throw;
        }
        $!method := $method;

        @!headers := @headers;
        $!body := $body;
        $!secret := $secret;
        $!region = $region.lc;
        $!service = $service.lc;
        
        # Map the lowercased and trimmed header names to trimmed header values. Will throw
        # an exception if there is an error, let caller catch it.
        %!header_map = map_headers(@headers);

        # Now create a URI obj from the URI string and make sure that the method and host are set.
        $!uri = URI.new(:$uri);
        unless $!uri.scheme ne '' && $!uri.host ne '' {
            X::WebService::AWS::V4::ParseError.new(input => :$uri,err => 'cannot parse uri').throw;
        }

        # If the $X_Amz_Date_key is not found, map_headers would have thrown an exception.
        # parse_amz_date will also throw an exception of the header value cannot be parsed,
        # let caller catch it.
        $!amz_date = parse_amz_date(%!header_map{$X_Amz_Date_key});
    }

    # Transform the Str array of headers into a hash where lc keys are mapped to normalized vals.
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
        for $Host_key, $X_Amz_Date_key -> $k {
            unless %header_map{$k}:exists {
                X::WebService::AWS::V4::ParseError.new(input => @headers.join("\n"),err => $k ~ ' header required').throw;
            }
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

    # Use this to get the yyyymmdd for a DateTime for use in various signing contexts.
    our sub amz_date_yyyymmdd(DateTime:D $dt) returns Str:D is export {
        sprintf "%04d%02d%02d", $dt.utc.year, $dt.utc.month, $dt.utc.day;    
    }
    
    our sub parse_amz_date(Str:D $s) returns DateTime:D is export {
        if $s ~~ / ^(\d ** 4)(\d ** 2)(\d ** 2)T(\d ** 2)(\d ** 2)(\d ** 2)Z$ / {
            return DateTime.new(year=>$0,
                                month=>$1,
                                day=>$2,
                                hour=>$3,
                                minute=>$4,
                                second=>$5,
                                formatter=>&amz_date_formatter);
        } else {
            X::WebService::AWS::V4::ParseError.new(input => $s,err => 'cannot parse X-Amz-Date').throw;
        }
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
    
    method canonical_request() returns Str:D is export {
        ($!method,
         self.canonical_uri(),
         self.canonical_query(),
         self.canonical_headers(),
         self.signed_headers(),
         sha256_base16($!body)).join("\n");
    }
    
    # STEP 2 STRING TO SIGN

    method credential_scope() returns Str:D is export {
        (amz_date_yyyymmdd($!amz_date),
         $!region,
         $!service,
         $Termination_str).join('/');
    }
    
    method string_to_sign() returns Str:D is export {
        my $cr = self.canonical_request();
        my $cr_sha256 = sha256_base16($cr);
        ($HMAC_name,
         $!amz_date.Str,
         self.credential_scope(),
         $cr_sha256).join("\n");
    }

    # STEP 3 CALCULATE THE AWS SIGNATURE

    method signature() returns Str:D is export {
        my $kdate = hmac($Auth_version ~ $!secret,amz_date_yyyymmdd($!amz_date),&sha256);
        my $kregion = hmac($kdate,$!region,&sha256);
        my $kservice = hmac($kregion,$!service,&sha256);
        my $ksigning = hmac($kservice,$Termination_str,&sha256);
        hmac-hex($ksigning,self.string_to_sign(),&sha256);
    }
}

