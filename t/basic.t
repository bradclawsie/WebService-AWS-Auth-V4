use v6;
use Test;
use URI;
use WebService::AWS::V4;

my Str @headers = "Host:iam.amazonaws.com",
   "Content-Type:application/x-www-form-urlencoded; charset=utf-8",
   "My-header1:    a   b   c ",
   "X-Amz-Date:20150830T123600Z",
   "My-Header2:    \"a     b   c\"";

my Str @missing_host_header = @headers[1 .. @headers.end];

my Str @malformed_headers = ( "Host iam.amazonaws.com" );

my $canonical_headers = "content-type:application/x-www-form-urlencoded; charset=utf-8\nhost:iam.amazonaws.com\nmy-header1:a b c\nmy-header2:\"a     b   c\"\nx-amz-date:20150830T123600Z\n";

my $signed_headers = "content-type;host;my-header1;my-header2;x-amz-date";

lives-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'https://iam.amazonaws.com/', headers => @headers);
}, 'correctly initialize well-formed obj';

dies-ok {
    my $v4 = WebService::AWS::V4.new(method => '', body => '', uri => 'https://iam.amazonaws.com/', headers => @headers);
}, 'caught exception when trying to initialize with missing method';

dies-ok {
    my $v4 = WebService::AWS::V4.new(method => 'PUT', body => '', uri => 'https://iam.amazonaws.com/', headers => @headers);
}, 'caught exception when trying to initialize with bad method';

dies-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => '', headers => @headers);
}, 'caught exception when trying to initialize with missing uri';

dies-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'htt', headers => @headers);
}, 'caught exception when trying to initialize with malformed uri';

dies-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'https://iam.amazonaws.com/home/documents+and+settings?a/z=b&C=d', headers => @missing_host_header);
}, 'caught exception on missing host header';

dies-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'https://iam.amazonaws.com/home/documents+and+settings?a/z=b&C=d', headers => @malformed_headers);
}, 'caught exception on malformed headers';

lives-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'https://iam.amazonaws.com/', headers => @headers);
    is $v4.canonical_uri(), '/', 'canonicalizes empty URI path';
    is $v4.canonical_query(), '', 'canonicalizes empty query';
}, 'correctly canonicalized empty';

lives-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'https://iam.amazonaws.com/home/documents+and+settings?a/z=b&C=d', headers => @headers);
    is $v4.canonical_uri(), '%2Fhome%2Fdocuments%2Band%2Bsettings', 'canonicalizes nonempty URI path';
    is $v4.canonical_query(), 'C=d&a%2Fz=b', 'canonicalizes nonempty query';
}, 'correctly canonicalized nonempty query';

dies-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'https://iam.amazonaws.com/home/documents+and+settings?ab&C=d', headers => @headers);
    my $q = $v4.canonicalize_query();
}, 'caught exception on malformed key-value query pair';

lives-ok {
    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'https://iam.amazonaws.com/home/documents+and+settings?a/z=b&C=d', headers => @headers);
    is $v4.canonical_headers(), $canonical_headers, 'match canonical headers';
    is $v4.signed_headers(), $signed_headers, 'match signed headers';
}, 'correctly canonicalized headers';

lives-ok {
    my Str @headers = "Host:iam.amazonaws.com",
   "Content-Type:application/x-www-form-urlencoded; charset=utf-8",
   "X-Amz-Date:20150830T123600Z";

    my $v4 = WebService::AWS::V4.new(method => 'GET', body => '', uri => 'https://iam.amazonaws.com/?Action=ListUsers&Version=2010-05-08', headers => @headers);

    my $cr = $v4.canonical_request();
    my $cr_sha256 = WebService::AWS::V4::sha256_base16($cr);
    is WebService::AWS::V4::sha256_base16($cr), 'f536975d06c0309214f805bb90ccff089219ecd68b2577efef23edd43b7e1a59', 'match aws test signature for canonical request';
}, 'correctly match canonical request test from aws';
