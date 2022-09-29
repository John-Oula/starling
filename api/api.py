import base64
import datetime
import hashlib
import hmac
import json
import os
from aws import VolcAuth
import requests
from flask import Flask, request, url_for, redirect, jsonify
from requests.auth import HTTPBasicAuth
from github import Github, GithubIntegration

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
NSPACE_ID = '39880'
OP_ID = 2100225925

app_id = 239753
# Read the  certificate
with open(os.path.normpath(os.path.expanduser('../certs/github/private_key.pem')), 'r') as cert_file:
    app_key = cert_file.read()

# Create an GitHub integration instance
git_integration = GithubIntegration(app_id, app_key)


# volc_auth = VolcAuth(access_key=access_key, secret_access_key=secret_key, region=region, service=service, host=host)


def sign(key, msg):
    return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()


def getSignatureKey(key, dateStamp, regionName, serviceName):
    kDate = sign((key).encode('utf-8'), dateStamp)
    kRegion = sign(kDate, regionName)
    kService = sign(kRegion, serviceName)
    kSigning = sign(kService, 'request')
    return kSigning


def generate_auth_headers(method, canonical_querystring, body, canonical_uri, secret_key, region, service, access_key,
                          host):
    t = datetime.datetime.utcnow()
    date = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')  # Date w/o time, used in credential scope

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
        'Authorization': authorization_header
    }
    return headers


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

# Check file extension
def checkFileExtension(arr):
    l = []
    for filepath in arr:
        filepath_split = filepath.split('/')
        file = filepath_split[len(filepath_split)-1]
        if file.endswith('.json'):
            l.append(filepath)
            return l

# Receive push webhook notifications
# create project and task


# This endpoint listen to webhook notifications
# from Github when files are pushed to the  repository

@app.route("/push", methods=['POST', 'GET'])
def push():
    global changed_files
    response = request.get_json()
    print(response)
    res_args = request.args
    content_list_b64 = []
    texts = []  #
    request_texts = []  #

    # Get the committed file paths according to commit type
    # Directory path
    dir_path = os.path.join(app.root_path + '/projects/repos')

    try:
        added_files = response['head_commit']['added']
        changed_files = response['head_commit']['modified']
        removed_files = response['head_commit']['removed']

        owner = response['repository']['owner']['name']
        repo = response['repository']['name']

        os.mkdir(os.path.join(dir_path, repo))


    except:
        pass

    # Fetch base64 encoded files from GitHub REST API
    # Using the list of file paths in changed_files
    # Append each json object to  content_list_b64
    for path in changed_files:



        git = Github(
            login_or_token=git_integration.get_access_token(git_integration.get_installation(owner, repo).id).token)
        repository = git.get_repo(f"{owner}/{repo}").get_contents(path=path,ref="main")
        # filename = repository.name
        # f = open(os.path.join(app.root_path, 'projects/repos/%s' % (repo), filename), 'w')
        file_to_string = repository.decoded_content.decode('utf-8')
        # f.write(file_to_string)

        # f.close()

        # Convert bytes to string
        # Convert JSON file to Dict
        # Add to list
        to_dict = json.loads(file_to_string)
        texts.append(to_dict)

    # Replace file's keys with "key" key
    # Replace file's key's value with "content" key

    for i, j in texts[0].items():
        new_obj = {}
        new_obj["key"] = i
        new_obj["content"] = j

        request_texts.append(new_obj)
    print(request_texts)
    ##### AUTH #####

    body = {"projectId": res_args["projectId"], "taskId": res_args["taskId"], "texts": request_texts}

    canonical_uri = '/'

    canonical_querystring = request_parameters

    auth_headers = generate_auth_headers('POST', canonical_querystring, body, canonical_uri,
                                         secret_key, region,
                                         service, access_key, host)

    # ************* SEND THE REQUEST *************
    request_url = endpoint + '?' + canonical_querystring

    re = requests.post(request_url, headers=auth_headers, data=json.dumps(body).encode('utf-8').decode())

    print('\nRESPONSE+++++++++++++')
    # print(re.status_code)
    print(re.text)


    return '', 200


@app.route("/hook", methods=['POST'])
def hook():
    response = request.get_json()
    content_list_b64 = []
    texts = []  #
    request_texts = []  #
    owner = response['repository']['owner']['login']
    repo = response['repository']['name']
    # Get a git connection as a Github App
    config = {
        "url": "http://example.com",
        "content_type": "json"
    }

    git = Github(
        login_or_token=git_integration.get_access_token(git_integration.get_installation(owner, repo).id).token)
    repo = git.get_repo(f"{owner}/{repo}").create_hook(name="web", events=['push'], active=True, config=config)
    print(repo)

    return '', 200


@app.route("/publish", methods=['POST', 'GET'])
def publish():
    response_data = request.data

    response = response_data.decode('utf-8')

    json_response = json.loads(response)


    projectId = json_response["projectId"]
    args = request.args.to_dict()
    # projectId = 4918
    token_url = 'https://starling-public.zijieapi.com/v3/get_auth_token/%s/%s/%s/%s/' % (
        args['key'], OP_ID, projectId, NSPACE_ID)

    res = requests.post(token_url)
    token = res.json()['data']['token']

    headers = {
        'Authorization': token
    }
    # Fetch and download resource files
    locale = 'zh-CN'

    copy_url = 'https://starling-public.zijieapi.com/text_test2/%s/%s' % (NSPACE_ID, locale)
    pull_copy = requests.get(copy_url, headers=headers)
    contents = pull_copy.json()['message']['data']
    # Base64 encode the contents
    # PUT contents back to the repository
    # Merge contents
    # b64_contents = base64.b64encode(json.dumps(contents, ensure_ascii=False).encode('utf-8')).decode()
    # print(contents)

    repo_url = args['repo_url']
    # Get file sha prop for the updated file
    # Generate parameters from the repo_url
    req_sha = requests.get(repo_url, auth=HTTPBasicAuth(username, PAT))

    owner = repo_url.split('/')[3]
    repo = repo_url.split('/')[4]

    # path_list = repo_url.split('/')[7:]
    # path = ""
    git = Github(
        login_or_token=git_integration.get_access_token(git_integration.get_installation(owner, repo).id).token)
    repository = git.get_repo(f"{owner}/{repo}").create_pull(
                                                title='Translation Strings',
                                                body='Updated Translation strings',
                                                base='main',
                                                head='main',
                                                draft=False

    )
    # for i in path_list:
    #     i = '/' + i
    #     path += i

    # data = {
    #     "owner": owner,
    #     "sha": req_sha.json()['sha'],
    #     "repo": repo,
    #     "path": path,
    #     "message": "%s translations" % locale,
    #     "content": b64_contents
    #
    # }
    # print(data['path'])

    # res = requests.put(repo_url, auth=HTTPBasicAuth(username, PAT), data=json.dumps(data))


    return '', 200


if __name__ == '__main__':
    app.run()
