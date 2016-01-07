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
}, 'caught exception on malformed key-value query pair';

dies-ok {
    my %h = map_headers(("foo:bar"));
}, 'caught excpetion on missing host header';

my Str @headers = "Host:iam.amazonaws.com",
   "Content-Type:application/x-www-form-urlencoded; charset=utf-8",
   "My-header1:    a   b   c ",
   "X-Amz-Date:20150830T123600Z",
   "My-Header2:    \"a     b   c\"";

my $canonical_headers = "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\nmy-header1:a b c\nmy-header2:\"a     b   c\"\nx-amz-date:20150830T123600Z\n";

is awsv4_canonicalize_headers(map_headers(@headers)), $canonical_headers, 'match example canonical headers';

my $signed_headers = "content-type;host;my-header1;my-header2;x-amz-date\n";

is awsv4_signed_headers(map_headers(@headers)), $signed_headers, 'match example signed headers'
