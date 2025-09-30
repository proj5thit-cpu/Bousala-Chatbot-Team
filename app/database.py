from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy import CheckConstraint



db = SQLAlchemy()

# -----------------------
# Database Models
# -----------------------

# models.py
class User(db.Model):
    __tablename__ = 'Users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), nullable=False, unique=True)
    email = db.Column(db.String(120), nullable=True, unique=True)  
    password = db.Column(db.String(255), nullable=False)           
    is_guest = db.Column(db.Boolean, nullable=False, default=False) 
    age_group = db.Column(db.String(20), nullable=True)      
    gender = db.Column(db.String(15), nullable=True)  

    posts = db.relationship('Post', back_populates='user', cascade="all, delete-orphan")

class Post(db.Model):
    __tablename__ = 'Posts'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    time = db.Column(db.String(100), nullable=False)

    
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)
    user = db.relationship('User', back_populates='posts')

    # Form fields 
    state = db.Column(db.String(80), nullable=False)            
    locality = db.Column(db.String(80), nullable=True)           # only for Khartoum/Gezira
    misinfo_type = db.Column(db.String(80), nullable=False)      
    followup = db.Column(db.String(120), nullable=True)          
    decision = db.Column(db.Boolean, default=False, nullable=False)  # did it lead to a decision?

    danger_level = db.Column(
        db.String(10),
        db.CheckConstraint("danger_level IN ('High','Medium','Low')"),
        nullable=False
    )

    content = db.Column(db.Text, nullable=False)

    media_items = db.relationship('Media', back_populates='post', cascade="all, delete-orphan")


class Media(db.Model):
    __tablename__ = 'Media'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    media_type = db.Column(db.String(20), nullable=False)  # image, audio, video

    # Foreign key to Posts
    post_id = db.Column(db.Integer, db.ForeignKey('Posts.id'), nullable=False)

    # Relationship to post
    post = db.relationship('Post', back_populates='media_items')




class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('Users.id'), nullable=False)  # Who receives it
    message = db.Column(db.String(255), nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)



# -----------------------
# Initialization Function
# -----------------------

def init_db(app):
    """Initialize the database with the Flask app."""
    db.init_app(app)
    with app.app_context():
        db.create_all()


# -----------------------
# Helper Functions
# -----------------------
def insert_post(form, user_id, media_filenames=None):
    """Insert a new post with all fields into the database and return its ID."""
    post = Post(
        content=form.get("story"),
        user_id=user_id,
        state=form.get("region"),
        locality=form.get("locality"),
        misinfo_type=form.get("misinfo"),
        followup=form.get("followup"),
        decision=form.get("decision"),
        danger_level=form.get("danger")
    )

    db.session.add(post)
    db.session.flush()  # get post.id before commit

    # Handle media if any
    if media_filenames:
        for filename, media_type in media_filenames:
            media = Media(
                filename=filename,
                media_type=media_type,
                post_id=post.id
            )
            db.session.add(media)

    db.session




def insert_media(filename, media_type, post_id):
    """Insert a new media file linked to a post."""
    media = Media(filename=filename, media_type=media_type, post_id=post_id)
    db.session.add(media)
    db.session.commit()


def get_all_posts():
    """Get all posts with their media."""
    posts = Post.query.outerjoin(Media).order_by(Post.created_at.desc(), Post.id.desc()).all()
    return posts


# -----------------------
# Run Standalone
# -----------------------

if __name__ == "__main__":
    from flask import Flask
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    init_db(app)
    print("✅ Database initialized successfully.")
