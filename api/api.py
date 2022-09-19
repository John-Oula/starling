
from flask import Flask , request

app = Flask(__name__)

# Receive push webhook notifications
# create project and task
@app.route("/push",methods=['POST','GET'])
def push():
    print(request.json)
    return '', 200

if __name__ == '__main__':

    app.run()