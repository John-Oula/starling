import sys, os, base64, datetime, hashlib, hmac
import requests # pip install requests


class AuthHeader(object):
    def __init__(self):
        self.algorithm = 'HMAC-SHA256'
    def sign(self,sk, msg):
        return hmac.new(sk, msg.encode('utf-8'), hashlib.sha256).digest()

    def getSignatureKey(self,sk, dateStamp, regionName, serviceName):
        kDate = self.sign((sk).encode('utf-8'), dateStamp)
        kRegion = self.sign(kDate, regionName)
        kService = self.sign(kRegion, serviceName)
        kSigning = self.sign(kService, 'request')
        return kSigning

    def date(self):
        # Create a date for headers and the credential string
        t = datetime.datetime.utcnow()
        datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope
        return datestamp

    def datestamp(self):
        # Create a date for headers and the credential string
        t = datetime.datetime.utcnow()
        date = t.strftime('%Y%m%dT%H%M%SZ')
        return  date

    def canonical_headers(self,host):


        # Step 2: Create canonical URI--the part of the URI from domain to query
        # string (use '/' if no path)


        # Step 3: Create the canonical query string. In this example (a GET request),
        # request parameters are in the query string. Query string values must
        # be URL-encoded (space=%20). The parameters must be sorted by name.
        # For this example, the query string is pre-formatted in the request_parameters variable.

        # Step 4: Create the canonical headers and signed headers. Header names
        # must be trimmed and lowercase, and sorted in code point order from
        # low to high. Note that there is a trailing \n.

        # Step 5: Create the list of signed headers. This lists the headers
        # in the canonical_headers list, delimited with ";" and in alpha order.
        # Note: The request can include any headers; canonical_headers and
        # signed_headers lists those that you want to be included in the
        # hash of the request. "Host" and "x-date" are always required.
        canonical_headers = 'host:' + host + '\n' + 'x-date:' + AuthHeader().datestamp() + '\n'
        print(AuthHeader().datestamp())
        return canonical_headers

    def canonical_request(self,method,body,canonical_uri,canonical_querystring,signed_headers,host):
        # Step 6: Create payload hash (hash of the request body content). For GET
        # requests, the payload is an empty string ("").

        payload_hash = hashlib.sha256(body.encode('utf-8')).hexdigest()

        # Step 7: Combine elements to create canonical request
        canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + self.canonical_headers(host) + '\n' + signed_headers + '\n' + payload_hash
        return canonical_request

    def string_to_sign(self,algorithm,region,service):
        # ************* TASK 2: CREATE THE STRING TO SIGN*************
        # Match the algorithm to the hashing algorithm you use, either SHA-1 or
        # SHA-256 (recommended)
        global credential_scope
        print(self.date())

        credential_scope = AuthHeader().datestamp() + '/' + region + '/' + service + '/' + 'request'
        string_to_sign = algorithm + '\n' + self.date() + '\n' + credential_scope + '\n'
        print(AuthHeader().datestamp())

        return  string_to_sign

    def signature(self,secret_key, region, service):
        # ************* TASK 3: CALCULATE THE SIGNATURE *************
        # Create the signing key using the function defined above.
        signing_key = self.getSignatureKey(secret_key, AuthHeader().datestamp(), region, service)
        print(AuthHeader().datestamp())

        # Sign the string_to_sign using the signing_key
        signature = hmac.new(signing_key, (self.string_to_sign(self.algorithm,region=region,service=service)).encode('utf-8'), hashlib.sha256).hexdigest()
        return signature

    def generate_auth_header(self,signature,access_key,signed_headers):
        # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************
        # The signing information can be either in a query string value or in
        # a header named Authorization. This code shows how to use a header.
        # Create authorization header and add to request headers
        authorization_header = self.algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature

        # The request can include any headers, but MUST include "host", "x-date",
        # and (for this scenario) "Authorization". "host" and "x-date" must
        # be included in the canonical_headers and signed_headers, as noted
        # earlier. Order here is not significant.
        # Python note: The 'host' header is added automatically by the Python 'requests' library.
        headers = {
            "content-type": 'application/json',
            'x-date': AuthHeader().date(),
            'Authorization': authorization_header
        }
        print(self.date)
        return headers

        # ************* SEND THE REQUEST *************
        # request_url = endpoint + '?' + canonical_querystring





# print('\nBEGIN REQUEST++++++++++++++++++++++++++++++++++++')
# print('Request URL = ' + request_url)
# r = requests.post(request_url, headers=headers , data=body)
#
# print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
# print('Response code: %d\n' % r.status_code)
# print(r.text)
# print(r.json())
# print(r)
