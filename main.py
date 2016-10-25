import requests
import os
from flask import Flask, request
import json
import sys

app = Flask(__name__)

def download_file(name, url):
    # TODO - Exception handling for 404 and no directory
    f = open('file/'+name+'.jpg','wb')
    f.write(requests.get(url).content)
    f.close()

@app.route('/',methods=['POST'])
def foo():
   data = json.loads(request.data)
   print data
   name = data['name']
   url = data['url']

   try:
        download_file(name, url)
        return "OK"
   except:
       # you sunk my battleship
        print "Unexpected error:", sys.exc_info()[0]
        raise

if __name__ == '__main__':
   app.run()
