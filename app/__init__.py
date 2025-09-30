import os
from flask import Flask
from dotenv import load_dotenv
from .database import db, init_db  # SQLAlchemy database

load_dotenv()

# -----------------------
# Media classification
# -----------------------
def classify_media(file):
    """Return ('image'|'audio'|'video'|None, ext) based on mimetype or extension."""
    if not file or not file.filename:
        return None, None
    filename = file.filename
    ext = (filename.rsplit('.', 1)[-1] or '').lower()
    mt = (file.mimetype or '').lower()
    if mt.startswith('image/') or ext in ALLOWED_IMAGE:
        return 'image', ext
    if mt.startswith('audio/') or ext in ALLOWED_AUDIO:
        return 'audio', ext
    if mt.startswith('video/') or ext in ALLOWED_VIDEO:
        return 'video', ext
    return None, ext

# -----------------------
# Flask App Factory
# -----------------------
def create_app():
    app = Flask(__name__)
    
    # Secret key
    app.config['SECRET_KEY'] = 'your-secret-key'
    
    # SQLAlchemy config
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Where to save media (under static/uploads so it's web-accessible)
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'static', 'uploads')
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Allowed file types
    global ALLOWED_IMAGE, ALLOWED_AUDIO, ALLOWED_VIDEO
    ALLOWED_IMAGE = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    ALLOWED_AUDIO = {'mp3', 'wav', 'm4a', 'ogg'}
    ALLOWED_VIDEO = {'mp4', 'mov', 'webm', 'mkv'}
    
    # Initialize SQLAlchemy
    init_db(app)
    
    # Register blueprint
    from .routes import main
    app.register_blueprint(main)

    return app
