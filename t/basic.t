use v6;
use Test;
use WebService::AWS::V4;

is awsv4_canonicalize_uri(''), '/', 'canonicalizes empty uri str';
