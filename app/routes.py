import os 
import pytz
import json
import requests
import faiss
import re
import sqlite3
from functools import wraps
import requests
from sqlalchemy.orm import joinedload
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for, session, g, send_from_directory, current_app
from flask import current_app, send_file
import secrets
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import uuid
from datetime import datetime
from werkzeug.utils import secure_filename
from . import classify_media
from .database import db, User ,Post, Media  , Notification
from .utils import classify_media
import numpy as np
import pickle
from flask import abort
from io import BytesIO
import pandas as pd




main = Blueprint("main", __name__)

# Load .env
load_dotenv()

main = Blueprint('main', __name__)

# Get absolute path safely
TREE_PATH = os.path.join(os.path.dirname(__file__), "data", "decision_tree.json.")



def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            lang = request.args.get('lang', 'ar')
            flash('Please log in first.' if lang=='en' else 'الرجاء تسجيل الدخول أولاً.', 'warning')
            return redirect(url_for('main.login', lang=lang))
        return view(*args, **kwargs)
    return wrapped



OPENAI_API_KEY = os.getenv("OPENAI_API_KEY") 
OPENAI_API_URL = "https://api.openai.com/v1/chat/completions" 
DEFAULT_MODEL = "gpt-3.5-turbo" 
if not OPENAI_API_KEY:
    print("⚠ Warning: OPENAI_API_KEY not set — chatbot will not work until it's set.")



def call_openai(payload):
    if not OPENAI_API_KEY:
        return {"error": "Server: OPENAI_API_KEY not configured."}

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(
            OPENAI_API_URL,
            headers=headers,
            json=payload,
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print("❌ OpenAI request failed:", e)
        return {"error": str(e)}




# ==== Password & Phone Validation ====
PASSWORD_REGEX = re.compile(r'^(?=.*[A-Z])(?=.*\d).{6,}$')
PHONE_REGEX = re.compile(r'^\+?\d{8,15}$')

def valid_password(pw):
    return bool(PASSWORD_REGEX.match(pw))

def valid_phone(phone):
    return bool(PHONE_REGEX.match(phone))


# --- Pages ------------------------------------------------
@main.route('/')
@main.route('/home')
def home():
    lang = request.args.get('lang', 'ar')
    return render_template('home.html', lang=lang)


@main.route('/home_fully')
def home_fully():
    lang = request.args.get('lang', 'ar')
    return render_template('home_fully.html', lang=lang)


@main.route('/about')
def about():
    lang = request.args.get('lang', 'ar')
    return render_template('about.html', lang=lang)

@main.route('/guidebot')
def guidebot():
    lang = request.args.get('lang', 'ar')
    return render_template('guidebot.html', lang=lang)

# ==== Register ====
@main.route('/register', methods=['GET', 'POST'])
def register():
    lang = request.args.get('lang', 'ar')

    if request.method == 'POST':
        username = (request.form.get('username') or '').strip()
        email = (request.form.get('email') or '').strip()
        password = request.form.get('password') or ''

        errors = []
        if not username:
            errors.append("Username is required." if lang == 'en' else "اسم المستخدم مطلوب.")
        if not email:
            errors.append("Email is required." if lang == 'en' else "البريد الإلكتروني مطلوب.")
        if not password:
            errors.append("Password is required." if lang == 'en' else "كلمة المرور مطلوبة.")
        if password and not valid_password(password):
            errors.append(
                "Password must be at least 6 characters, include 1 uppercase and 1 number."
                if lang == 'en' else
                "كلمة المرور يجب أن تكون 6 أحرف على الأقل وتحتوي على حرف كبير واحد ورقم واحد."
            )

        # Check duplicates
        if User.query.filter_by(username=username).first():
            errors.append("Username already exists." if lang == 'en' else "اسم المستخدم موجود بالفعل.")
        if User.query.filter_by(email=email).first():
            errors.append("Email already exists." if lang == 'en' else "البريد الإلكتروني موجود بالفعل.")

        # If errors, reload register form
        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('register.html', lang=lang, form=request.form)

        # Save new user
        pw_hash = generate_password_hash(password)
        user = User(username=username, email=email, password=pw_hash, is_guest=False)
        db.session.add(user)
        db.session.commit()

        # ✅ Auto login after register
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_guest'] = False

        flash("Registration successful." if lang == 'en' else "تم إنشاء الحساب بنجاح.", 'success')
        return redirect(url_for('main.home_fully', lang=lang))

    return render_template('register.html', lang=lang)



# ==== Login ====
@main.route('/login', methods=['GET','POST'])
def login():
    lang = request.args.get('lang', 'ar')
    if request.method == 'POST':
        username_or_email = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''

        if not username_or_email or not password:
            flash("Username/Email and password are required." if lang=='en' else "اسم المستخدم/البريد الإلكتروني وكلمة المرور مطلوبان.", 'danger')
            return render_template('login.html', lang=lang, form=request.form)

        # ✅ Find user by username OR email
        user = User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()

        if not user or not check_password_hash(user.password, password):
            flash("Invalid username/email or password." if lang=='en' else "اسم المستخدم/البريد الإلكتروني أو كلمة المرور غير صحيح.", 'danger')
            return render_template('login.html', lang=lang, form=request.form)

        # ✅ Store session data including is_guest
        session['user_id'] = user.id
        session['username'] = user.username
        session['is_guest'] = user.is_guest

        flash(
            f"Welcome, {user.username}!" if lang=='en' else f"مرحباً، {user.username}!",
            'success'
        )
        return redirect(url_for('main.home_fully', lang=lang))

    return render_template('login.html', lang=lang)



@main.route('/logout')
def logout():
    lang = request.args.get('lang', 'ar')
    session.clear()
    flash("You have been logged out." if lang=='en' else "تم تسجيل الخروج.", 'info')
    return redirect(url_for('main.home', lang=lang))
 


@main.route('/guest-start')
def guest_start():
    lang = request.args.get('lang', 'ar')

    # Create a display name like Guest-7fa3
    username = f"Guest-{secrets.token_hex(2)}"

    # Random password (unused) just to satisfy NOT NULL
    random_pw = generate_password_hash(secrets.token_urlsafe(16))

    user = User(
        username=username,
        email=None,
        password=random_pw,
        is_guest=True
    )
    db.session.add(user)
    db.session.commit()

    # Session flags
    session['user_id'] = user.id
    session['username'] = username
    session['is_guest'] = True

    return redirect(url_for('main.home_fully', lang=lang))



@main.route('/post', methods=['GET', 'POST'])
def post():
    lang = request.args.get('lang', 'ar')
    errors = {}

    if request.method == 'POST':
        # Ensure user is logged in
        user_id = session.get('user_id')
        if not user_id:
            return redirect(url_for('main.login', lang=lang))

        # Collect form data
        age = request.form.get('age')
        gender = request.form.get('gender')
        state = request.form.get('state')
        locality = request.form.get('locality')
        misinfo = request.form.get('misinfo')
        followup = request.form.get('followup')
        decision = request.form.get('decision')
        danger = request.form.get('danger')
        content = (request.form.get('story') or "").strip()
        time = request.form.get('time') 

        # Validation
        if not age: errors["age"] = "Age is required" if lang == "en" else "العمر مطلوب"
        if not gender: errors["gender"] = "Gender is required" if lang == "en" else "الجنس مطلوب"
        if not state: errors["state"] = "Region is required" if lang == "en" else "الولاية مطلوبة"
        if not time: errors["time"] = "Time is required" if lang == "en" else "الوقت مطلوب"
        if not misinfo: errors["misinfo"] = "Type of misinformation is required" if lang == "en" else "نوع المعلومة مطلوب"
        if not decision: errors["decision"] = "Decision selection is required" if lang == "en" else "القرار مطلوب"
        if not danger: errors["danger"] = "Danger level is required" if lang == "en" else "مستوى الخطورة مطلوب"
        if not content: errors["story"] = "Story cannot be empty" if lang == "en" else "القصّة مطلوبة"

        if errors:
            return render_template("post.html", lang=lang, errors=errors,
                                   age=age, gender=gender, state=state,
                                   locality=locality, misinfo=misinfo,
                                   followup=followup, decision=decision,
                                   danger=danger, story=content, time=time)

        # Update user profile
        user = User.query.get(user_id)
        if user:
            if age: user.age = age
            if gender: user.gender = gender

        # Create new Post
        new_post = Post(
            content=content,
            user_id=user_id,
            state=state,
            locality=locality,
            misinfo_type=misinfo,
            followup=followup,
            decision=(decision == "True"),
            danger_level=danger,
            created_at=datetime.utcnow(),
            time=time
        )
        db.session.add(new_post)
        db.session.flush()

        # Handle uploaded media
        files = request.files.getlist('media')
        upload_folder = os.path.join('app', 'uploads')
        os.makedirs(upload_folder, exist_ok=True)

        for file in files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                filepath = os.path.join(upload_folder, filename)
                file.save(filepath)

                media_item = Media(
                    filename=filename,
                    media_type=file.mimetype.split('/')[0],  
                    post_id=new_post.id
                )
                db.session.add(media_item)
        
        # Notify other users
        other_users = User.query.filter(User.id != user_id, User.is_guest == False).all()
        for u in other_users:
            notif = Notification(user_id=u.id, message="New Story Has Been Posted.")
            db.session.add(notif)
        
        db.session.commit()

        return redirect(url_for('main.posts_list', lang=lang))

    return render_template("post.html", lang=lang, errors={})




@main.app_context_processor
def inject_notifications():
    user_id = session.get("user_id")
    notifs = []
    unread_count = 0

    if user_id:
        notifs = Notification.query.filter_by(user_id=user_id).order_by(Notification.created_at.desc()).limit(5).all()
        unread_count = Notification.query.filter_by(user_id=user_id, is_read=False).count()

    return dict(notifications=notifs, unread_count=unread_count)


@main.route("/notifications/read_all")
@login_required
def read_all_notifications():
    user_id = session.get("user_id")
    Notification.query.filter_by(user_id=user_id, is_read=False).update({"is_read": True})
    db.session.commit()
    return redirect(request.referrer or url_for("main.home"))


# ==== Serve uploaded files ====
@main.route('/uploads/<filename>')
def uploaded_file(filename):
    upload_folder = os.path.join(current_app.root_path, 'uploads')
    return send_from_directory(upload_folder, filename)





# ==== Posts ====
@main.route('/posts', methods=['GET'])
def posts_list():
    lang = request.args.get('lang', 'ar')

    filter_by = request.args.get('filter')
    value = request.args.get('value')

    # Start with all posts
    query = Post.query.options(
        joinedload(Post.user),
        joinedload(Post.media_items)
    )

    # Apply filtering
    if filter_by == "type":
        query = query.filter(Post.misinfo_type == value)
    elif filter_by == "followup":
        query = query.filter(Post.followup == value)
    elif filter_by == "danger":
        query = query.filter(Post.danger_level == value)
    elif filter_by == "state":
        query = query.filter(Post.state == value)
    elif filter_by == "time":
        query = query.filter(Post.time == value)
    elif filter_by == "owner":
        if value == "me" and session.get("user_id"):
            query = query.filter(Post.user_id == session["user_id"])

    posts = query.order_by(Post.created_at.desc(), Post.id.desc()).all()

    return render_template('posts_list.html', lang=lang, posts=posts)


# === Edit Post ===
@main.route('/post/<int:post_id>/edit', methods=['GET', 'POST'])
def edit_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Only the owner can edit
    if post.user_id != session.get('user_id'):
        abort(403)

    if request.method == 'POST':
        post.content = request.form.get('story')
        

        db.session.commit()
        flash("✅ Your post was updated successfully!", "success")
        return redirect(url_for('main.posts_list'))

    return render_template('edit_post.html', post=post)


# === Delete Post ===
@main.route('/post/<int:post_id>/delete', methods=['POST'])
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)

    # Only the owner can delete
    if post.user_id != session.get('user_id'):
        abort(403)

    db.session.delete(post)
    db.session.commit()
    flash("🗑 Your post was deleted successfully.", "success")
    return redirect(url_for('main.posts_list'))



# ==== Chatbot Helpers ====

# ==== Load the tree ====
def load_tree():
    try:
        with open(TREE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        current_app.logger.error("❌ Could not load decision_tree.json: %s", e)
        return {}

decision_tree = load_tree()

# ==== Serialize node for frontend ====
def serialize_node(node_obj, lang="en"):
    """
    node_obj: dict from JSON
    returns localized structure for frontend:
      - questions/sub_question -> { type, question, options: [{key,label}] }
      - leaf -> { type, advice: [..], stories: { good: [...], bad: [...] } }
    """
    if not isinstance(node_obj, dict):
        return {"type": "leaf", "advice": [], "stories": {"good": [], "bad": []}}

    out = {"type": node_obj.get("type", "leaf")}

    # Questions & sub questions
    if out["type"] in ("question", "sub_question"):
        q = node_obj.get("question", {})
        out["question"] = q.get(lang) if isinstance(q, dict) else q

        opts = []
        for key, label in node_obj.get("options", {}).items():
            if isinstance(label, dict):
                lab = label.get(lang, label.get("en", key))
            else:
                lab = label
            opts.append({"key": key, "label": lab})
        out["options"] = opts
        return out

    # Leaf nodes
    if out["type"] == "leaf":
        # advice
        adv = node_obj.get("advice", {})
        if isinstance(adv, dict):
            out["advice"] = adv.get(lang, adv.get("en", []))
        else:
            out["advice"] = adv or []

        # good stories from JSON (if present)
        stories_obj = node_obj.get("stories", {}) or {}
        good_obj = stories_obj.get("good", {}) if isinstance(stories_obj, dict) else {}
        good_list = []
        if isinstance(good_obj, dict):
            good_list = good_obj.get(lang, good_obj.get("en", []))
        elif isinstance(good_obj, list):
            good_list = good_obj

        out["stories"] = {"good": good_list, "bad": []}

        # fetch BAD stories from DB by main misinfo_type mapping:
        # prefer node_obj['misinfo_type'] (set in JSON on leafs) else fallback to node_obj['id']
        misinfo_type = node_obj.get("misinfo_type") or node_obj.get("id")
        if misinfo_type:
            try:
                # Post model must have column `misinfo_type` and `content`
                bad_posts = Post.query.filter_by(misinfo_type=misinfo_type).order_by(Post.created_at.desc()).all()
                out["stories"]["bad"] = [p.content for p in bad_posts if getattr(p, "content", None)]
            except Exception as e:
                current_app.logger.exception("Failed to load bad posts for %s: %s", misinfo_type, e)
                out["stories"]["bad"] = []
        return out

    # default
    out["advice"] = []
    out["stories"] = {"good": [], "bad": []}
    out["options"] = []
    return out

@main.route("/api/guide/set_lang", methods=["POST"])
def guide_set_lang():
    data = request.get_json() or {}
    lang = data.get("lang", "en")
    if lang not in ("en", "ar"):
        lang = "en"
    session["guide_lang"] = lang
    session["guide_path"] = ["start"]
    return jsonify({"ok": True, "lang": lang})

@main.route("/api/guide/start", methods=["GET"])
def guide_start():
    lang = request.args.get("lang", session.get("guide_lang", "en"))
    session["guide_lang"] = lang
    session["guide_path"] = ["start"]
    node = decision_tree.get("start", decision_tree.get("fallback", {}))
    return jsonify(serialize_node(node, lang))


@main.route("/api/guide/choose", methods=["POST"])
def guide_choose():
    data = request.get_json() or {}
    lang = data.get("lang", session.get("guide_lang", "en"))
    choice = data.get("choice", "")
    path = session.get("guide_path", ["start"])

    if not choice:
        return jsonify({"error": "missing_choice"}), 400

    
    node = decision_tree.get(choice)

 
    if not node:
        for pkey in path:
            parent_node = decision_tree.get(pkey, {})
            opts = parent_node.get("options", {}) if isinstance(parent_node, dict) else {}
            if choice in opts:
                node = decision_tree.get(choice)
                break
            
            for k, v in opts.items():
                if isinstance(v, dict):
                    lab = v.get(lang, v.get("en", k))
                else:
                    lab = v
                if lab == choice:
                    node = decision_tree.get(k)
                    break
            if node:
                break

    if not node:
        node = decision_tree.get("fallback", {})

    path.append(choice)
    session["guide_path"] = path

    return jsonify(serialize_node(node, lang))




@main.route('/get_stories/<decision_type>', methods=['GET'])
def get_stories(decision_type):
    
    stories = Post.query.filter_by(misinfo_type=decision_type).all()

    story_list = []
    for s in stories:
        story_list.append({
            "id": s.id,
            "content": s.content,
            "author": s.user.username if s.user else "Anonymous",
            "created_at": s.created_at.strftime("%Y-%m-%d")
        })
    return jsonify(story_list)



# --- ADMIN CREDENTIALS (REPLACE / MOVE to env in production) ---
ADMIN_USERNAME = "ADMIN"
ADMIN_PASSWORD = "ADMIN123SLMT"

# --- decorator to protect admin routes ---
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin_logged_in"):
            return redirect(url_for("main.admin_login"))
        return f(*args, **kwargs)
    return decorated

# ---- Admin login route ----
@main.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    lang = request.args.get('lang', 'ar')
    if request.method == 'POST':
        username = (request.form.get('username') or "").strip()
        password = (request.form.get('password') or "").strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            session['admin_username'] = username
            flash("Welcome, admin.", "success")
            return redirect(url_for('main.admin_dashboard'))
        else:
            flash("Invalid admin username or password.", "danger")

    return render_template('admin_login.html', lang=lang)

# ---- Admin logout ----
@main.route('/admin/logout')
@admin_required
def admin_logout():
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    flash("Admin logged out.", "success")
    return redirect(url_for('main.admin_login'))

# ---- Dashboard (list posts) ----
@main.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    lang = request.args.get('lang', 'ar')
    posts = Post.query.options(
        joinedload(Post.user),
        joinedload(Post.media_items)
    ).order_by(Post.created_at.desc(), Post.id.desc()).all()

    return render_template('admin_dashboard.html', lang=lang, posts=posts)


@main.route('/admin/export')
@admin_required
def admin_export():
    posts = Post.query.options(
        joinedload(Post.user),
        joinedload(Post.media_items)
    ).order_by(Post.created_at.desc(), Post.id.desc()).all()

    rows = []
    for p in posts:
        rows.append({
            "Post ID": p.id,
            "Created At": p.created_at.strftime("%Y-%m-%d %H:%M:%S") if p.created_at else "",
            "User ID": p.user_id,
            "Gender": (p.user.gender if p.user else ""),
            "Age": (p.user.age_group if p.user else ""),
            "Story Time": p.time or "",
            "State": p.state or "",
            "Locality": p.locality or "",
            "Misinfo Type": p.misinfo_type or "",
            "Followup": p.followup or "",
            "Decision": "Yes" if p.decision else "No",
            "Danger Level": p.danger_level or "",
            "Content": p.content or ""
        })

    # create DataFrame and write to bytes buffer
    df = pd.DataFrame(rows, columns=[
        "Post ID", "Created At", "User ID", "Gender", "Age", "Story Time",
        "State", "Locality", "Misinfo Type", "Followup", "Decision",
        "Danger Level", "Content"
    ])

    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='posts')
    output.seek(0)

    fname = f"posts_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.xlsx"
    return send_file(
        output,
        as_attachment=True,
        download_name=fname,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
