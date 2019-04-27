from . import db


class Posts(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('users.id'))
    photo=db.Column(db.String(80))
    caption=db.Column(db.String(255))
    created_on=db.Column(db.DateTime)
    
    def get_id(self):
        try:
            return unicode(self.postid)  # python 2 support
        except NameError:
            return str(self.postid) # python 3 support
       

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80))
    password = db.Column(db.String(255))
    firstname = db.Column(db.String(80))
    lastname = db.Column(db.String(80))
    email = db.Column(db.String(255))
    location = db.Column(db.String(100))
    biography = db.Column(db.String(255))
    profile_photo = db.Column(db.String(80))
    joined_on = db.Column(db.String(20))
    

    def is_authenticated(self):
        return True

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def get_id(self):
        try:
            return unicode(self.id)  # python 2 support
        except NameError:
            return str(self.id)  # python 3 support

    def __repr__(self):
        return '<User %r>' % (self.username)


class Likes(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id=db.Column(db.Integer,db.ForeignKey('posts.id'))
    
    def get_id(self):
        try:
            return unicode(self.id)  # python 2 support
        except NameError:
            return str(self.id)  # python 3 support


    
class Follows(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    user_id=db.Column(db.Integer,db.ForeignKey('users.id'))
    follower_id=db.Column(db.Integer,db.ForeignKey('users.id'))
    
    def get_id(self):
        try:
            return unicode(self.followid)  # python 2 support
        except NameError:
            return str(self.followid) # python 3 support
