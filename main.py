import requests
import os
from flask import Flask, request
import json
import sys
import cloudinary
import cloudinary.uploader
import cloudinary.api

app = Flask(__name__)

cloudinary.config(
      cloud_name = 'imgrab',
      api_key = '',
      api_secret = ''
    )

@app.route('/',methods=['POST'])
def upload_image():
   print request.data
   data = json.loads(request.data)
   print data
   name = data['name']
   url = data['url']

   try:
        # download_file(name, url)
        cloudinary.uploader.upload(str(url), public_id =str(name))
        print cloudinary.utils.cloudinary_url(str(name)+".jpg")
        return cloudinary.utils.cloudinary_url(str(name)+".jpg")

   except:
       # you sunk my battleship
        print "Unexpected error:", sys.exc_info()[0]
        raise

if __name__ == '__main__':
   app.run()
