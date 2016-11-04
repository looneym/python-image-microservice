#!/usr/bin/env python
import os

import requests
import json
import sys
import cloudinary
import cloudinary.uploader
import cloudinary.api

from flask import Flask, abort, request, jsonify, g, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

# CDN API utility
cloudinary.config(
      cloud_name = 'imgrab',
      api_key = '',
      api_secret = ''
    )


class Image(db.Model):
    __tablename__ = 'images'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(100), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = relationship("User", back_populates="images")

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))
    images = relationship( "Image", order_by=Image.id, back_populates="user")

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None    # valid token, but expired
        except BadSignature:
            return None    # invalid token
        user = User.query.get(data['id'])
        return user

@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if user:
        g.user = user
        g.authenticated_via = "token"
        return True

    # try to authenticate with username/password
    user = User.query.filter_by(username=username_or_token).first()
    if not user or not user.verify_password(password):
        return False
    else:
        g.user = user
        g.authenticated_via = "password"
        return True


@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        abort(400)    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('get_user', id=user.id, _external=True)})


@app.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/token')
@auth.login_required
def get_auth_token():
    if g.authenticated_via == "password":
        token = g.user.generate_auth_token(600)
        return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        abort(403)


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})


@app.route('/api/dump')
@auth.login_required
def dump_db():
    results = Image.query.all()
    images = []

    for result in results:
        images.append(result.url)

    data = json.dumps(images)
    return data

@app.route('/api/image',methods=['POST'])
@auth.login_required
def upload_image():
   print request.data
   data = json.loads(request.data)

   name = data['name']
   url = data['url']

   try:
        cloudinary.uploader.upload(str(url), public_id =str(name))
        cloudinary_url =  cloudinary.utils.cloudinary_url(str(name)+".jpg")[0]

        image = Image(url=cloudinary_url, user_id=g.user.id)
        db.session.add(image)
        db.session.commit()

        return cloudinary_url
   except:
       # you sunk my battleship!
        print "Unexpected error:", sys.exc_info()[0]
        raise

if __name__ == '__main__':
    db.create_all()
    # if not os.path.exists('db.sqlite'):
    #     db.create_all()
    app.run(debug=True)
