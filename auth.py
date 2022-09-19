import datetime
import hashlib
import hmac

import pytz
from volcengine.util.Util import Util
from volcengine.auth.MetaData import MetaData

from volcengine.auth import MetaData
from volcengine.auth import SignerV4
import requests

auth = SignerV4
meta = MetaData
uri = "open.volcengineapi.com"
url = "https://open.volcengineapi.com"
timestamp = datetime.datetime.now(tz=pytz.timezone('UTC')).strftime("%Y%m%dT%H%M%SZ")
sk = "T0RReE1EQXlZMk0wWVdNMU5ETTBZVGhsTkdFd00yVmxPVGRsWkdRMll6VQ=="
ak = "AKLTMDc3MGY5ZmI4NDI4NDRjZmE0ZjkyMDhjZDQ0YzI0Yzg"


class MyObject:
    def __init__(self, d=None):
        if d is not None:
            for key, value in d.items():
                setattr(self, key, value)


def authorization(method,query,headers,hex_body,signed_headers,uri):

    return method + '\n' + uri + '\n' + query + '\n' + headers + '\n' + signed_headers + '\n' + hex_body

def canonical_request():
    global signed_headers
    global query
    query = "Actions=DocumentCreate&Version=2021-05-21"
    signed_headers = "x-date;host"
    can_uri="/"

    # CanonicalHeaders = CanonicalHeadersEntry0 + CanonicalHeadersEntry1 + ... + CanonicalHeadersEntryN
    # CanonicalHeadersEntry = Lowercase(HeaderName) + ':' + Trimall(HeaderValue) + '\n'

    headers = "x-date:%s&host:%s" % (timestamp, uri)
    body=""
    # hex_body = hmac.new(bytes(body.encode('UTF-8')), digestmod=hashlib.sha256).hexdigest()
    hex_body = Util.sha256(body)
    # print(authorization("POST",query,headers,hex_body,signed_headers,can_uri))
    return authorization("POST",query,headers,hex_body,signed_headers,can_uri)


def test(func):

    return print(func)


def string_to_sign(algorithm,date,scope,canonical_req):
    global credential_scope
    date = date[:8]
    region = 'cn-beijing'
    scope = scope
    
    hashed_canon_req = Util.sha256(canonical_req)
    credential_scope =  '/'.join([date, region, scope, 'request'])

    signing_str = '\n'.join([algorithm, timestamp, credential_scope, hashed_canon_req])
    return signing_str

# test(
#     string_to_sign('HMAC-SHA256',timestamp,'i18n_openapi',canonical_request())
# )

def signing_key():
    return  auth.SignerV4.get_signing_secret_key_v4(sk,timestamp,'ZH','i18n_openapi')

# test(signing_key())

def signature():
    global sign
    sign = auth.SignerV4.signature_v4(signing_key(),string_to_sign('HMAC-SHA256',timestamp,'i18n_openapi',canonical_request()))
    return  sign

# test(signature())

def authHeader():
## Authorization: HMAC-SHA256 Credential={AccessKeyId}/{CredentialScope}, SignedHeaders={SignedHeaders}, Signature={Signature}
    return 'Authorization: HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s' % (ak,credential_scope,signed_headers,sign)

# test(authHeader())

def api():
    string_to_sign('HMAC-SHA256', timestamp, 'i18n_openapi', canonical_request())
    signing_key()
    signature()
    a = authHeader()
    headers ={
        "Authorization": authHeader()
    }
    print(authHeader())
    params = {
        "Action":"DocumentCreate",
    "Version":"2021-05-21"
    }
    response = requests.post(url,params=params,headers=headers)
    return response.json()
test(api())
