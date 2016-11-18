#!/usr/bin/env python
import os
import requests
import json
import sys
import cloudinary
import cloudinary.uploader
import cloudinary.api

from flask import Flask, abort, request, jsonify, g, url_for, render_template, redirect
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.login import LoginManager, UserMixin,login_required, login_user, logout_user

from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)


########################################
##
##  Configuration and Setup
##
########################################

# configure flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = 'the quick brown fox jumps over the lazy dog'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True

# configure flask-login
login_manager = LoginManager()
login_manager.login_view = "/login"
login_manager.init_app(app)

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

# image CDN API utility
cloudinary.config(
      cloud_name = 'imgrab',
      api_key = '647421229246868',
      api_secret = 'OBB7DB6VftnH2b7oZ9MUQ6LpfLg'
    )

########################################
##
##  DB Models
##
########################################

class Image(db.Model):
    __tablename__ = 'images'
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(100), index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

    user = relationship("User", back_populates="images")

class User(db.Model, UserMixin):
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

    @classmethod
    def get(cls,id):
        user = User.query.filter_by(id=id).first()
        return user

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

########################################
##
##  Authentication utils
##
##  A Note on Authentication: this app uses http basic Authentication
##  for API endpoints. These are secured with the following function
##  decorator: @auth.login_required which will force a call to
##  @auth.verify_password
##
##  The application also uses flask-login for browser-based login using
##  forms and cookies. These views are secured with @login_required which
##  will attempt to load the user from the session cookie using
##  @login_manager.user_loader if a cookie is present and will redirect to
##  the login view otherwise
##
########################################

@login_manager.user_loader
def load_user(user_id):
    user = User.get(user_id)
    g.user = user
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

########################################
##
##  API Endpoints
##
########################################

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
    return (jsonify({'username': user.username}))

@app.route('/api/token')
@auth.login_required
def get_auth_token():
    if g.authenticated_via == "password":
        token = g.user.generate_auth_token(600)
        return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        abort(403)

@app.route('/api/image',methods=['POST'])
@auth.login_required
def upload_image():
   print request.data
   data = json.loads(request.data)
   # name = data['name']
   url = data['url']

   try:
        cloudinary_response = cloudinary.uploader.upload(str(url))
        cloudinary_url =  cloudinary_response['secure_url']
        image = Image(url=cloudinary_url, user_id=g.user.id)
        db.session.add(image)
        db.session.commit()
        return cloudinary_url
   except:
       # you sunk my battleship
        print "Unexpected error:", sys.exc_info()[0]
        raise

########################################
##
##  Webapp views
##
########################################

@app.route('/')
def show_homepage():
    return render_template('home.html')

@app.route('/about')
def show_about_page():
    return render_template('about.html')

@app.route('/help')
def show_help_page():
    return render_template('help.html')

@app.route('/images')
@login_required
def show_images():
    results = g.user.images
    results.reverse()
    urls = []

    for result in results:
        urls.append(result.url)

    images = json.dumps(urls)
    return render_template('images.html', images=images)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print username
        print password

        # try to authenticate with username/password
        user = User.query.filter_by(username=username).first()
        if not user or not user.verify_password(password):
            return redirect("/login")
        else:
            g.user = user
            g.authenticated_via = "password"
            login_user(g.user)

            if request.args.get("next") is not None:
                return redirect(request.args.get("next"))
            else:
                return redirect("/images")

    else:
        return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")

if __name__ == '__main__':
    db.create_all()
    # if not os.path.exists('db.sqlite'):
    #     db.create_all()
    app.run(debug=True, port=5000)
