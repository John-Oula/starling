import hmac
import hashlib
import datetime
import json

try:
    # python 2
    from urllib import quote
    from urlparse import urlparse
except ImportError:
    # python 3
    from urllib.parse import quote, urlparse

import requests

PAT = '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'
username = 'John-Oula'
method = 'POST'
service = 'i18n_openapi'
host = "open.volcengineapi.com"
region = 'cn-beijing'
endpoint = "https://open.volcengineapi.com"
request_parameters = 'Action=ProjectTaskSourceAdd&Version=2021-05-21'
content_type = 'application/json'

access_key = "AKLTMDc3MGY5ZmI4NDI4NDRjZmE0ZjkyMDhjZDQ0YzI0Yzg"
secret_key = "T0RReE1EQXlZMk0wWVdNMU5ETTBZVGhsTkdFd00yVmxPVGRsWkdRMll6VQ=="
signed_headers = 'host;x-date'
canonical_uri = '/'
canonical_querystring = request_parameters
algorithm = 'HMAC-SHA256'
NSPACE_ID = '39880'
OP_ID = 2100225925

def sign(key, msg):
    """
    Copied from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    """
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    """
    Copied from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
    """
    kDate = sign(('AWS4' + key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'request')
    return kSigning


class VolcAuth(requests.auth.AuthBase):
    """
    Auth class that allows us to connect to AWS services
    via Volcengine's signature version 4 signing process


    """

    def __init__(self,
                 access_key,
                 secret_access_key,
                 host,
                 region,
                 service):
        """
        Example usage for talking to an AWS Elasticsearch Service:

        VolcAuth(access_key='YOURKEY',
                        secret_access_key='YOURSECRET',
                        host='search-service-foobar.us-east-1.es.amazonaws.com',
                        region='us-east-1',
                        service='es',
                        )


        """
        self.access_key = access_key
        self.secret_access_key = secret_access_key
        self.host = host
        self.region = region
        self.service = service


    def __call__(self, r):
        """
        Adds the authorization headers required by Volcengine's signature
        version 4 signing process to the request.

        Adapted from https://docs.aws.amazon.com/general/latest/gr/sigv4-signed-request-examples.html
        """
        headers = self.get_request_headers_handler(r)
        r.headers.update(headers)
        return r

    def get_request_headers_handler(self, r):
        """
        Override get_request_headers_handler() if you have a
        subclass that needs to call get_request_headers() with
        an arbitrary set of AWS credentials. The default implementation
        calls get_request_headers() with self.access_key,
        self.secret_access_key
        """
        return self.get_request_headers(r=r,
                                            access_key=self.access_key,
                                            secret_access_key=self.secret_access_key
                                            )

    def get_request_headers(self, r, access_key, secret_access_key):
        """
        Returns a dictionary containing the necessary headers for Volcengine's
        signature version 4 signing process. An example return value might
        look like

            {
                'Authorization': 'HMAC-SHA256 Credential=YOURKEY/20160618/us-east-1/es/request, '
                                 'SignedHeaders=host;x-date, '
                                 'Signature=ca0a856286efce2a4bd96a978ca6c8966057e53184776c0685169d08abd74739',
                'x-date': '20160618T220405Z',
            }
        """
        # Create a date for headers and the credential string
        t = datetime.datetime.utcnow()
        date = t.strftime('%Y%m%dT%H%M%SZ')
        datestamp = t.strftime('%Y%m%d')  # Date w/o time for credential_scope

        canonical_uri = VolcAuth.get_canonical_path(r)

        canonical_querystring = VolcAuth.get_canonical_querystring(r)

        # Create the canonical headers and signed headers. Header names
        # and value must be trimmed and lowercase, and sorted in ASCII order.
        # Note that there is a trailing \n.
        canonical_headers = ('host:' + self.host + '\n' +
                             'x-date:' + date + '\n')


        # Create the list of signed headers. This lists the headers
        # in the canonical_headers list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; canonical_headers and
        # signed_headers lists those that you want to be included in the
        # hash of the request. "Host" and "x-date" are always required.
        signed_headers = 'host;x-date'


        # Create payload hash (hash of the request body content). For GET
        # requests, the payload is an empty string ('').
        body = r.body if r.body else bytes()

        try:
            body = body.encode('utf-8')
        except (AttributeError, UnicodeDecodeError):
            # On py2, if unicode characters in present in `body`,
            # encode() throws UnicodeDecodeError, but we can safely
            # pass unencoded `body` to execute hexdigest().
            #
            # For py3, encode() will execute successfully regardless
            # of the presence of unicode data
            body = body
        print(body)



        payload_hash = hashlib.sha256(body).hexdigest()

        # Combine elements to create create canonical request
        canonical_request = (r.method + '\n' + canonical_uri + '\n' +
                             canonical_querystring + '\n' + canonical_headers +
                             '\n' + signed_headers + '\n' + payload_hash)

        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        algorithm = 'HMAC-SHA256'
        credential_scope = (datestamp + '/' + self.region + '/' +
                            self.service + '/' + 'request')
        string_to_sign = algorithm + '\n' + date + '\n' + credential_scope + '\n' + hashlib.sha256(
            canonical_request.encode('utf-8')).hexdigest()
        # Create the signing key using the function defined above.
        signing_key = getSignatureKey(secret_access_key,
                                      datestamp,
                                      self.region,
                                      self.service)

        # Sign the string_to_sign using the signing_key
        string_to_sign_utf8 = string_to_sign.encode('utf-8')
        signature = hmac.new(signing_key,
                             string_to_sign_utf8,
                             hashlib.sha256).hexdigest()

        # The signing information can be either in a query string value or in
        # a header named Authorization. This code shows how to use a header.
        # Create authorization header and add to request headers
        authorization_header = (algorithm + ' ' + 'Credential=' + access_key +
                                '/' + credential_scope + ', ' + 'SignedHeaders=' +
                                signed_headers + ', ' + 'Signature=' + signature)

        headers = {

            'x-date': date,
            'Authorization': authorization_header,
            'content-type': 'application/json'

        }

        return headers

    @classmethod
    def get_canonical_path(cls, r):
        """
        Create canonical URI--the part of the URI from domain to query
        string (use '/' if no path)
        """
        parsedurl = urlparse(r.url)

        # safe chars adapted from boto's use of urllib.parse.quote
        # https://github.com/boto/boto/blob/d9e5cfe900e1a58717e393c76a6e3580305f217a/boto/auth.py#L393
        return quote(parsedurl.path if parsedurl.path else '/', safe='/-_.~')

    @classmethod
    def get_canonical_querystring(cls, r):
        """
        Create the canonical query string. According to AWS, by the
        end of this function our query string values must
        be URL-encoded (space=%20) and the parameters must be sorted
        by name.

        This method assumes that the query params in `r` are *already*
        url encoded.  If they are not url encoded by the time they make
        it to this function, AWS may complain that the signature for your
        request is incorrect.

        It appears elasticsearc-py url encodes query paramaters on its own:
            https://github.com/elastic/elasticsearch-py/blob/5dfd6985e5d32ea353d2b37d01c2521b2089ac2b/elasticsearch/connection/http_requests.py#L64

        If you are using a different client than elasticsearch-py, it
        will be your responsibility to urleconde your query params before
        this method is called.
        """
        canonical_querystring = ''

        parsedurl = urlparse(r.url)
        querystring_sorted = '&'.join(sorted(parsedurl.query.split('&')))

        for query_param in querystring_sorted.split('&'):
            key_val_split = query_param.split('=', 1)

            key = key_val_split[0]
            if len(key_val_split) > 1:
                val = key_val_split[1]
            else:
                val = ''

            if key:
                if canonical_querystring:
                    canonical_querystring += "&"
                canonical_querystring += u'='.join([key, val])


        return canonical_querystring
volc_auth = VolcAuth(access_key=access_key, secret_access_key=secret_key, region=region, service=service, host=host)

request_parameters = "Action=DocumentCreate&Version=2021-05-21"
body = {"projectName": "Second round test"}
re = requests.post(endpoint + '?' + request_parameters, json=body, auth=volc_auth)
print('api', re.request.body)
print(re.content)