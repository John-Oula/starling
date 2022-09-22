import base64
import datetime
import hashlib
import hmac
import json
import os

import requests
from flask import Flask, request, url_for, redirect, jsonify
from requests.auth import HTTPBasicAuth

app = Flask(__name__)


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


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign((key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'request')
    return kSigning
def date():
    # Create a date for headers and the credential string
    t = datetime.datetime.utcnow()
    datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope
    return datestamp


def datestamp():
    # Create a date for headers and the credential string
    t = datetime.datetime.utcnow()
    date = t.strftime('%Y%m%dT%H%M%SZ')
    return date


# Receive push webhook notifications
# create project and task
@app.route("/push",methods=['POST','GET'])
def push():

    response = request.get_json()
    content_list_b64 = []


    # Get the commits according to commit type

    try:
        added_files = response['head_commit']['added']
        changed_files = response['head_commit']['modified']
        removed_files = response['head_commit']['removed']

        owner = response['repository']['owner']['name']
        repo = response['repository']['name']

        # Directory path
        dir_path = os.path.join(app.root_path + '/projects/repos')

    except:
        pass

    try:
        os.mkdir(os.path.join(dir_path, repo))
    except:
        pass



    # Fetch file(s) base64 content from github REST API
    # Using the list of file paths stored in the above variables
    for path in changed_files:
        res = requests.get('https://api.github.com/repos/%s/%s/contents/%s' % (owner,repo,path),  auth = HTTPBasicAuth(username, PAT))
        content_list_b64.append(res.json())
        print(res.json())


    # From the content_list_b64
    # Fetch and Download the files
    # Save downloaded files
    texts = []
    request_texts = []
    for file in content_list_b64:
        file_content = base64.b64decode(file["content"])
        f = open(os.path.join(app.root_path, 'projects/repos/%s' % (repo), file['name']),'w')
        f.write(file_content.decode('utf-8'))

        f.close()

        # Convert bytes to string
        # Convert JSON file to Dict
        # Add to list
        file_to_string = file_content.decode('utf-8')
        to_dict = json.loads(file_to_string)
        texts.append(to_dict)



        # Replace file's keys with "key" key
        # Replace file's key's value with "content" key


    for i, j in texts[0].items():
        new_obj = {}
        new_obj["key"] = i
        new_obj["content"] = j

        request_texts.append(new_obj)


    ##### AUTH #####



    body = {"projectId": 4883, "taskId": "24279681" ,"texts":request_texts}
    t = datetime.datetime.utcnow()
    date = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    canonical_uri = '/'


    canonical_querystring = request_parameters


    canonical_headers = 'host:' + host + '\n' + 'x-date:' + date + '\n'

    signed_headers = 'host;x-date'



    payload_hash = hashlib.sha256(json.dumps(body).encode('utf-8')).hexdigest()

    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash


    algorithm = 'HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'request'
    string_to_sign = algorithm + '\n' + date + '\n' + credential_scope + '\n' + hashlib.sha256(
        canonical_request.encode('utf-8')).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************

    signing_key = getSignatureKey(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature


    headers = {
        "content-type": 'application/json',
        'x-date': date,
        'Authorization': authorization_header}

    # ************* SEND THE REQUEST *************
    request_url = endpoint + '?' + canonical_querystring


    r = requests.post(request_url, headers=headers, data=json.dumps(body))

    print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
    print( r.status_code)
    print(r.text)
    print(r.request.body)



    return '' , 200

@app.route("/auth",methods=['POST','GET'])
def auth():
    texts = []
    body = {"projectId": 4894, "taskId": "94830089" ,"texts":texts}
    t = datetime.datetime.utcnow()
    date = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

    canonical_uri = '/'


    canonical_querystring = request_parameters


    canonical_headers = 'host:' + host + '\n' + 'x-date:' + date + '\n'

    signed_headers = 'host;x-date'



    payload_hash = hashlib.sha256(json.dumps(body).encode('utf-8')).hexdigest()

    canonical_request = method + '\n' + canonical_uri + '\n' + canonical_querystring + '\n' + canonical_headers + '\n' + signed_headers + '\n' + payload_hash


    algorithm = 'HMAC-SHA256'
    credential_scope = datestamp + '/' + region + '/' + service + '/' + 'request'
    string_to_sign = algorithm + '\n' + date + '\n' + credential_scope + '\n' + hashlib.sha256(
        canonical_request.encode('utf-8')).hexdigest()

    # ************* TASK 3: CALCULATE THE SIGNATURE *************

    signing_key = getSignatureKey(secret_key, datestamp, region, service)

    # Sign the string_to_sign using the signing_key
    signature = hmac.new(signing_key, (string_to_sign).encode('utf-8'), hashlib.sha256).hexdigest()

    # ************* TASK 4: ADD SIGNING INFORMATION TO THE REQUEST *************

    authorization_header = algorithm + ' ' + 'Credential=' + access_key + '/' + credential_scope + ', ' + 'SignedHeaders=' + signed_headers + ', ' + 'Signature=' + signature


    headers = {
        "content-type": 'application/json',
        'x-date': date,
        'Authorization': authorization_header}

    # ************* SEND THE REQUEST *************
    request_url = endpoint + '?' + canonical_querystring


    r = requests.post(request_url, headers=headers, data=json.dumps(body))

    print('\nRESPONSE++++++++++++++++++++++++++++++++++++')
    print( r.status_code)
    print(r.text)
    print(r.request.body)
    return '' , 200

@app.route("/send_file",methods=['POST','GET'])
def send_file():

    file_path = os.path.abspath('test.json')
    f = open(file_path, 'wb')

    resp = requests.post(endpoint+'?'+request_parameters,data=body)

    return '' , 200

if __name__ == '__main__':

    app.run()