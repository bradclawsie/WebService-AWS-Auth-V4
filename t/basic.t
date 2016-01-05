use v6;
use Test;
use URI;
use WebService::AWS::V4;

is awsv4_canonicalize_uri(URI.new('')), '/', 'canonicalizes path from empty URI';
is awsv4_canonicalize_uri(URI.new('http://example.com')), '/', 'canonicalizes empty URI path';
is awsv4_canonicalize_uri(URI.new('http://example.com/')), '/', 'canonicalizes / URI path';
is awsv4_canonicalize_uri(URI.new('http://example.com/home/documents+and+settings')), '%2Fhome%2Fdocuments%2Band%2Bsettings', 'canonicalize nonempty URI str';

is awsv4_canonicalize_query(URI.new('')), '', 'canonicalize query from empty URI';
is awsv4_canonicalize_query(URI.new('http://example.com')), '', 'canonicalize query from empty URI query';
is awsv4_canonicalize_query(URI.new('http://example.com/')), '', 'canonicalize query from empty URI query';
is awsv4_canonicalize_query(URI.new('http://example.com/path?')), '', 'canonicalize query from empty URI query';
is awsv4_canonicalize_query(URI.new('http://example.com/path?a=b')), 'a=b', 'canonicalize query from URI';
is awsv4_canonicalize_query(URI.new('http://example.com/path?a=b&C=d')), 'C=d&a=b', 'canonicalize query from URI with sort';
is awsv4_canonicalize_query(URI.new('http://example.com/path?a/z=b&C=d')), 'C=d&a%2Fz=b', 'canonicalize query from URI with sort and escape';
is awsv4_canonicalize_query(URI.new('http://example.com/path?Action=ListUsers&Version=2010-05-08')), 'Action=ListUsers&Version=2010-05-08', 'canonicalize query from URI';

dies-ok {
    awsv4_canonicalize_query(URI.new('http://example.com/path?ab&c=d'));
}, 'caught exception on malformed key-value query pair'
