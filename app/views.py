"""
Flask Documentation:     http://flask.pocoo.org/docs/
Jinja2 Documentation:    http://jinja.pocoo.org/2/documentation/
Werkzeug Documentation:  http://werkzeug.pocoo.org/documentation/
This file creates your application.
"""

import os, datetime, random, re, jwt
from app import app
from app import db, login_manager, token_key
from functools import wraps
from .forms import ProfileForm, LoginForm, PostForm
from .models import Users, Posts, Follows, Likes
from flask import render_template, request, redirect, url_for, flash,jsonify, g, make_response,session,abort
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename

###
# Rounting for your application
###



@app.route('/')
def home():
    """Render website's home page."""
    return render_template('index.html')


@app.route('/about/')
def about():
    """Render the website's about page."""
    return render_template('about.html')
    
''' Authorization here'''
def requires_auth(f):
  @wraps(f)
  def decorated(*args, **kwargs):
    auth = request.headers.get('Authorization', None)
    if not auth:
      return jsonify({'code': 'authorization_header_missing', 'description': 'Authorization header is expected'}), 401

    parts = auth.split()

    if parts[0].lower() != 'bearer':
      return jsonify({'code': 'invalid_header', 'description': 'Authorization header must start with Bearer'}), 401
    elif len(parts) == 1:
      return jsonify({'code': 'invalid_header', 'description': 'Token not found'}), 401
    elif len(parts) > 2:
      return jsonify({'code': 'invalid_header', 'description': 'Authorization header must be Bearer + \s + token'}), 401

    token = parts[1]
    try:
         payload = jwt.decode(token, token_key)
         get_user = Users.query.filter_by(id=payload['user_id']).first()

    except jwt.ExpiredSignature:
        return jsonify({'code': 'token_expired', 'description': 'token is expired'}), 401
    except jwt.DecodeError:
        return jsonify({'code': 'token_invalid_signature', 'description': 'Token signature is invalid'}), 401

    g.current_user = user = get_user
    return f(*args, **kwargs)

  return decorated
    
@app.route("/api/users/register", methods=["POST"]) 
def register():
    
    form = ProfileForm()
    
    if request.method == 'POST'and form.validate_on_submit():
            username = form.username.data
            password = form.password.data
            firstname = form.firstname.data
            lastname = form.lastname.data
            email = form.email.data
            location = form.location.data
            bio = form.bio.data
            joined_on = datetime.date.today()
            
            photo = form.photo.data
            filename = secure_filename(photo.filename)
            photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            # userid = generateUserId(firstname, lastname)
            
            # user = Users(id=userid,password=password, firstname=firstname, lastname=lastname,
            #           email= email,location= location, biography=bio, profile_photo=filename, joined_on=joined_on)
            
            user = Users(password=password, firstname=firstname, lastname=lastname,
                       email= email,location= location, biography=bio, profile_photo=filename, joined_on=joined_on)
                
            db.session.add(user)
            db.session.commit()
            
            return jsonify(response=[{'message':'Successfully created account'}])
    error_retrieval = form_errors(form)
    error = [{'errors': error_retrieval}]
    return jsonify(errors=error)
    
@app.route("/api/auth/login", methods=["POST"])
def login():
    form = LoginForm()
    if request.method == "POST" and form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Users.query.filter_by(username=username, password=password).first()
        user = db.session.qury(Users).filter_by(username=username, password=password).first()
        if user is None:
            return jsonify(errors=[{'error':['Incorrect Username or Password.']}])
         
        login_user(user)  
        payload = {'user_id' : user.id}
        token = jwt.encode(payload, token_key)
        return jsonify(response=[{'message':'Log in successful','token': token, 'userid': user.id}])
    error_collection = form_errors(form)
    error = [{'errors': error_collection}]
    return jsonify(errors=error)
    
@app.route("/api/auth/logout", methods=["GET"])
@requires_auth
@login_required
def logout():
    if request.method == 'GET':
        logout_user()
    return jsonify(response=[{'message':'User successfully logged out.'}])

@app.route('/api/users/<userid>/posts', methods=['POST','GET'])
@requires_auth
@login_required
def post(userid):
    if request.method == 'POST':
        try:
            json = request.get_json()
            if not json or not json.get('user_id') or not json.get('photo') or not json.get('description'):
                return jsonify(
                    {"message": "error valuable data missing"}
                )
            else:
                user_id=json['user_id']
                photo=json['photo']
                filename=secure_filename(photo.filename)
                caption= json['description']
                created_on=datetime.date.today()
                
                filename = secure_filename(photo.filename)
                photo.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                
                Post = Posts(user_id,filename,caption,created_on)
                
                db.session.add(post)
                db.session.commit()
                
                return jsonify({
                    "message" : "Successfully created a new post"
                })
        except Exception as error:
            return json({'message': 'something went wrong'})
            
    if request.method == 'GET':
        try:
            posts = db.session.query(Posts).filter_by(user_id=userid).all()
            return jsonify(posts)
        except Exception as error:
            return jsonify({'message': 'something went wrong'})

@app.route('/api/users/<userid>/follow', methods=['POST'])
@requires_auth
@login_required
def follow(userid):
    try:
        json = request.get_json()
        if not json or not json.get('user_id') or not json.get('follower_id'):
            return jsonify(
                {"message": "error valuable data missing"}
            )
        else:
            user_id=json['user_id']
            follower_id=json['follower_id']
            
            follow = Follows(user_id, follower_id)
            
            db.session.add(follow)
            db.session.commit()

            return jsonify({
                "message":"You are now following that user"
            })
    except Exception as error:
        return jsonify({'message': 'something went wrong'})

@app.route('/api/posts', methods=['GET'])
@requires_auth
@login_required
def posts():
    try:
        posts = db.session.query(Posts).all()
        return jsonify(posts)
    except Exception as error:
        return jsonify({'message': 'something went wrong'})

@app.route('/api/users/<postid>/like', methods=['POST'])
@requires_auth
@login_required
def like(postid):
    json = request.get_json()
    try:
        if not json or not json.get('user_id') or not json.get('post_id'):
            return jsonify(
                {"message": "error valuable data missing"}
            )
        else:
            user_id=json['user_id']
            post_id=json['post_id']
            
            like = Likes(user_id,post_id)
            
            db.session.add(like)
            db.session.commit()
            
            return jsonify({
                "message":"Post liked!",
                "Likes": db.session.query(Likes).filter_by(post_id = json['post_id']).first()
            })
    except Exception as error:
        return jsonify({'message': 'something went wrong'})


@app.route('/<file_name>.txt')
def send_text_file(file_name):
    """Send your static text file."""
    file_dot_text = file_name + '.txt'
    return app.send_static_file(file_dot_text)

@app.after_request
def add_header(response):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    response.headers['X-UA-Compatible'] = 'IE=Edge,chrome=1'
    response.headers['Cache-Control'] = 'public, max-age=0'
    return response


@app.errorhandler(404)
def page_not_found(error):
    """Custom 404 page."""
    return render_template('404.html'), 404


if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port="8080")
    