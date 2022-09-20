import os

import requests
from flask import Flask, request, url_for, redirect, jsonify
from requests.auth import HTTPBasicAuth
from starling import AuthHeader

app = Flask(__name__)

PAT = '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'
username = 'John-Oula'
method = 'POST'
service = 'i18n_openapi'
host = "open.volcengineapi.com"
region = 'cn-beijing'
endpoint = "https://open.volcengineapi.com"
request_parameters = 'Action=ProjectTaskTextImport&Version=2021-05-21'
content_type = 'application/json'
body = '{"projectId":"4894","taskId":"94830089"}'
access_key = "AKLTMDc3MGY5ZmI4NDI4NDRjZmE0ZjkyMDhjZDQ0YzI0Yzg"
secret_key = "T0RReE1EQXlZMk0wWVdNMU5ETTBZVGhsTkdFd00yVmxPVGRsWkdRMll6VQ=="
signed_headers = 'host;x-date'
canonical_uri = '/'
canonical_querystring = request_parameters
algorithm = 'HMAC-SHA256'

# Receive push webhook notifications
# create project and task
@app.route("/push",methods=['POST','GET'])
def push():

    response = request.get_json()
    download_url_list = []

    # Get the commits according to commit type


    added_files = response['head_commit']['added']
    changed_files = response['head_commit']['modified']
    removed_files = response['head_commit']['removed']

    owner = response['repository']['owner']['name']
    repo = response['repository']['name']

    # Directory path
    dir_path = os.path.join(app.root_path +'/projects/repos')

    os.mkdir(os.path.join(dir_path, repo))


    # Fetch file(s) download url from github REST API
    # Using the list of file paths stored in the above variables
    for path in changed_files:
        res = requests.get('https://api.github.com/repos/%s/%s/contents/%s' % (owner,repo,path),  auth = HTTPBasicAuth(username, PAT))
        download_url_list.append(res.json())
        print(res.json())

    # From the download_url_list
    # Fetch and Download the files
    # Save downloaded files
    for file in download_url_list:
        res = requests.get(file['download_url'])
        open(file['name'], "wb").write(res.content)
        f = open(os.path.join(app.root_path, 'projects/repos/%s' % (repo), file['name']),'wb')
        f.write(res.content)
        f.close()




    return '' , 200

@app.route("/auth",methods=['POST','GET'])
def auth():

    canonical_headers = AuthHeader().canonical_headers(host=host)
    canonical_request = AuthHeader().canonical_request(method='POST',body=body,canonical_uri=canonical_uri,canonical_querystring=canonical_querystring,signed_headers=signed_headers,host=host)
    string_to_sign = AuthHeader().string_to_sign(algorithm=algorithm,region=region,service=service)
    signature =  AuthHeader().signature(secret_key=secret_key,region=region,service=service)
    auth_header= AuthHeader().generate_auth_header(access_key=access_key,signed_headers=signed_headers,signature=signature)
    print(auth_header)

    headers = {
            "content-type": 'application/json',
            'x-date': AuthHeader().date(),
            'Authorization': auth_header
        }
    request_url = endpoint + '?' + canonical_querystring

    r = requests.post(request_url, headers=auth_header , data=body)
    print(r.json())
    return '' , 200

@app.route("/send_file",methods=['POST','GET'])
def send_file():

    file_path = os.path.abspath('test.json')
    f = open(file_path, 'wb')

    resp = requests.post(endpoint+'?'+request_parameters,data=body)

    return '' , 200

if __name__ == '__main__':

    app.run()