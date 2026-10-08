import hashlib
import hmac
import os
import re
import secrets
import shutil
import smtplib
import sqlite3
import subprocess
import time
from email.message import EmailMessage
from functools import wraps

from flask import (Flask, abort, flash, g, jsonify, redirect, render_template_string,
                   request, send_from_directory, session)
from werkzeug.security import check_password_hash, generate_password_hash

try:  # optional: pip install pillow  (auto-resizes uploads to Instagram size)
    from PIL import Image, ImageOps
except ImportError:
    Image = None

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB per upload (videos need room)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
DB = os.environ.get("DB_PATH", "social.db")
UPLOADS = os.path.abspath(os.environ.get("UPLOAD_DIR", "uploads"))
os.makedirs(UPLOADS, exist_ok=True)
FFMPEG = shutil.which("ffmpeg")  # Termux: pkg install ffmpeg  (needed to crop/trim videos)

# ---- email (for verification codes) ----
# Set these environment variables to send real emails, e.g. with Gmail:
#   SMTP_HOST=smtp.gmail.com SMTP_PORT=587 SMTP_USER=you@gmail.com SMTP_PASS=<app password>
# Without SMTP_HOST the code is printed in the server console (handy while testing).
SMTP_HOST = os.environ.get("SMTP_HOST")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER")
SMTP_PASS = os.environ.get("SMTP_PASS")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER or "no-reply@social.local")
CODE_TTL = 600        # a code works for 10 minutes
RESEND_WAIT = 30      # seconds between code emails
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def init_db():
    with sqlite3.connect(DB) as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users(
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS posts(
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, body TEXT NOT NULL,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS follows(
                follower INTEGER, followed INTEGER, PRIMARY KEY(follower, followed));
            CREATE TABLE IF NOT EXISTS likes(
                user_id INTEGER, post_id INTEGER, PRIMARY KEY(user_id, post_id));
            CREATE TABLE IF NOT EXISTS comments(
                id INTEGER PRIMARY KEY, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
                body TEXT NOT NULL, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS comment_likes(
                user_id INTEGER, comment_id INTEGER, PRIMARY KEY(user_id, comment_id));
            CREATE TABLE IF NOT EXISTS stories(
                id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, kind TEXT NOT NULL,
                media TEXT, body TEXT, bg INTEGER DEFAULT 0,
                created TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS story_likes(
                user_id INTEGER, story_id INTEGER, PRIMARY KEY(user_id, story_id));
            CREATE TABLE IF NOT EXISTS story_views(
                user_id INTEGER, story_id INTEGER, PRIMARY KEY(user_id, story_id));
            CREATE TABLE IF NOT EXISTS story_replies(
                id INTEGER PRIMARY KEY, story_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
                body TEXT NOT NULL, created TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
            CREATE TABLE IF NOT EXISTS email_codes(
                user_id INTEGER PRIMARY KEY, code_hash TEXT NOT NULL, expires INTEGER NOT NULL,
                attempts INTEGER DEFAULT 0, sent INTEGER NOT NULL);
            """
        )
        # upgrade older databases without losing data
        for table, col, decl in [
            ("users", "avatar", "TEXT"),
            ("users", "email", "TEXT"),
            ("users", "bio", "TEXT"),
            ("users", "verified", "INTEGER DEFAULT 0"),
            ("posts", "image", "TEXT"),
            ("posts", "video", "TEXT"),
            ("posts", "is_reel", "INTEGER DEFAULT 0"),
            ("posts", "allow_dl", "INTEGER DEFAULT 0"),
            ("posts", "is_ad", "INTEGER DEFAULT 0"),
            ("posts", "ad_url", "TEXT"),
            ("posts", "repost_of", "INTEGER"),
            ("comments", "parent_id", "INTEGER"),
        ]:
            cols = [r[1] for r in c.execute(f"PRAGMA table_info({table})")]
            if col not in cols:
                c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {decl}")
                if (table, col) == ("users", "verified"):
                    # accounts that existed before email verification keep working
                    c.execute("UPDATE users SET verified=1")
        c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL")


def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if not session.get("uid"):
            return redirect("/login")
        return f(*a, **k)

    return wrapper


PUBLIC = {"login", "register", "verify", "resend_code"}  # open without an account


@app.before_request
def require_login():
    if request.endpoint in PUBLIC:
        return None
    if not current_user():  # not logged in, or the account no longer exists
        session.clear()
        return redirect("/login")


# ---------- email verification ----------
def hash_code(uid, code):
    return hmac.new(app.secret_key.encode(), f"{uid}:{code}".encode(), hashlib.sha256).hexdigest()


def send_email(to, subject, text):
    """Send an email. Returns True if really sent, False if only printed to the console."""
    if not SMTP_HOST:
        print(f"\n=== EMAIL (SMTP not configured) ===\nTo: {to}\n{subject}\n{text}\n===================================\n",
              flush=True)
        return False
    try:
        msg = EmailMessage()
        msg["From"], msg["To"], msg["Subject"] = SMTP_FROM, to, subject
        msg.set_content(text)
        if SMTP_PORT == 465:
            s = smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=15)
        else:
            s = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15)
            s.starttls()
        with s:
            if SMTP_USER:
                s.login(SMTP_USER, SMTP_PASS or "")
            s.send_message(msg)
        return True
    except Exception as e:
        print("email failed:", e, flush=True)
        return False


def issue_code(uid, email):
    """Create a fresh 6-digit code for the account and email it."""
    code = f"{secrets.randbelow(10 ** 6):06d}"
    now = int(time.time())
    db().execute(
        "INSERT OR REPLACE INTO email_codes(user_id,code_hash,expires,attempts,sent) VALUES(?,?,?,0,?)",
        (uid, hash_code(uid, code), now + CODE_TTL, now),
    )
    db().commit()
    return send_email(
        email, "Your Social verification code",
        f"Your verification code is {code}\n\nIt expires in {CODE_TTL // 60} minutes. "
        "If you didn't sign up, you can ignore this email.",
    )


def mask_email(e):
    if not e or "@" not in e:
        return ""
    a, b = e.split("@", 1)
    return a[0] + "***@" + b


# ---------- posts ----------
def fetch_posts(where="", args=(), uid=None):
    """Each row is shown as its original post; shares carry the sharer's name."""
    uid = uid or 0
    return db().execute(
        f"""SELECT o.id, o.user_id AS owner_id, o.body, o.image, o.video, o.is_reel, o.allow_dl, o.is_ad, o.ad_url,
            o.created, au.username, au.avatar,
            sh.username AS sharer,
            (SELECT COUNT(*) FROM likes l WHERE l.post_id=o.id) AS likes,
            (SELECT COUNT(*) FROM comments c WHERE c.post_id=o.id) AS comments,
            (SELECT COUNT(*) FROM posts r WHERE r.repost_of=o.id) AS shares,
            EXISTS(SELECT 1 FROM likes l WHERE l.post_id=o.id AND l.user_id=?) AS liked,
            EXISTS(SELECT 1 FROM posts r WHERE r.repost_of=o.id AND r.user_id=?) AS shared,
            EXISTS(SELECT 1 FROM follows f WHERE f.follower=? AND f.followed=o.user_id) AS following
            FROM posts p
            JOIN posts o ON o.id = COALESCE(p.repost_of, p.id)
            JOIN users au ON au.id = o.user_id
            LEFT JOIN users sh ON sh.id = p.user_id AND p.repost_of IS NOT NULL
            {where} ORDER BY p.id DESC LIMIT 50""",
        (uid, uid, uid, *args),
    ).fetchall()


def comment_rows(pid, uid):
    return db().execute(
        """SELECT c.id, c.body, c.created, c.parent_id, u.username, u.avatar,
           (SELECT COUNT(*) FROM comment_likes x WHERE x.comment_id=c.id) AS likes,
           EXISTS(SELECT 1 FROM comment_likes x WHERE x.comment_id=c.id AND x.user_id=?) AS liked
           FROM comments c JOIN users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.id""",
        (uid, pid),
    ).fetchall()


# ---------- image + video uploads ----------
def save_image(file):
    """Save a JPG/PNG/GIF/WebP (checked by file signature). Returns filename or None."""
    if not file or not file.filename:
        return None
    head = file.stream.read(12)
    file.stream.seek(0)
    if head.startswith(b"\xff\xd8\xff"):
        ext = "jpg"
    elif head.startswith(b"\x89PNG\r\n\x1a\n"):
        ext = "png"
    elif head[:6] in (b"GIF87a", b"GIF89a"):
        ext = "gif"
    elif head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        ext = "webp"
    else:
        return None
    name = f"{secrets.token_hex(16)}.{ext}"
    path = os.path.join(UPLOADS, name)
    if Image and ext != "gif":  # shrink big photos to max 1080px, like Instagram
        try:
            im = ImageOps.exif_transpose(Image.open(file.stream))
            im.thumbnail((1080, 1080))
            if ext == "jpg":
                im = im.convert("RGB")
            im.save(path, quality=85, optimize=True)
            return name
        except Exception:
            file.stream.seek(0)
    file.save(path)
    return name


def _num(name, default, lo, hi):
    """Read a number from the form, clamped to lo..hi."""
    try:
        v = float(request.form.get(name, default))
    except ValueError:
        return default
    return default if v != v else min(max(v, lo), hi)


def save_video(file, maxdur=60):
    """Save an MP4/MOV/WebM (checked by signature), applying the crop + trim chosen in the
    editor with ffmpeg. Without ffmpeg the original is saved as is. Returns filename or None."""
    if not file or not file.filename:
        return None
    head = file.stream.read(12)
    file.stream.seek(0)
    if head[4:8] == b"ftyp":
        ext = "mp4"
    elif head[:4] == b"\x1a\x45\xdf\xa3":
        ext = "webm"
    else:
        return None
    base = secrets.token_hex(16)
    if not FFMPEG:
        file.save(os.path.join(UPLOADS, f"{base}.{ext}"))
        return f"{base}.{ext}"

    tmp = os.path.join(UPLOADS, f"tmp_{base}.{ext}")
    out = os.path.join(UPLOADS, f"{base}.mp4")
    file.save(tmp)
    w, h = _num("vw", 1, 0.05, 1), _num("vh", 1, 0.05, 1)
    x, y = min(_num("vx", 0, 0, 1), 1 - w), min(_num("vy", 0, 0, 1), 1 - h)
    start, dur = _num("vs", 0, 0, 36000), _num("vd", maxdur, 1, maxdur)
    vf = (
        f"crop=trunc(iw*{w:.5f}/2)*2:trunc(ih*{h:.5f}/2)*2:"
        f"trunc(iw*{x:.5f}):trunc(ih*{y:.5f}),scale='min(720,iw)':-2"
    )
    cmd = [
        FFMPEG, "-y", "-ss", f"{start:.2f}", "-t", f"{dur:.2f}", "-i", tmp, "-vf", vf,
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "28", "-pix_fmt", "yuv420p",
        "-c:a", "aac", "-b:a", "96k", "-movflags", "+faststart", out,
    ]
    try:
        subprocess.run(cmd, check=True, timeout=180,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return f"{base}.mp4"
    except Exception:
        if os.path.exists(out):
            os.remove(out)
        return None
    finally:
        os.remove(tmp)


@app.route("/media/<name>")
def media(name):
    return send_from_directory(UPLOADS, name)  # supports Range requests, so videos can seek


@app.after_request
def secure_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.errorhandler(413)
def too_big(_):
    flash("That file is too large (max 50 MB).")
    return redirect(request.referrer or "/")


# ---------- templates ----------
BASE = """<!doctype html>
<meta name=viewport content="width=device-width,initial-scale=1,viewport-fit=cover">
<link rel=preconnect href="https://fonts.googleapis.com"><link rel=preconnect href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel=stylesheet>
<title>Social</title>
<style>
:root{--nav:64px;--red:#ed4956;--ink:#1f1f2e;--mut:#8a8a9a;--grad:linear-gradient(45deg,#f58529,#dd2a7b,#8134af)}
*{-webkit-tap-highlight-color:transparent}
body{font-family:"Inter","Poppins","Segoe UI",-apple-system,Roboto,Helvetica,Arial,sans-serif;color:var(--ink);
font-size:15px;line-height:1.45;letter-spacing:-.005em;-webkit-font-smoothing:antialiased;
max-width:470px;margin:0 auto;padding:20px 14px calc(var(--nav) + 40px);min-height:100vh;
background:radial-gradient(circle at 12% 8%,rgba(255,153,102,.38),transparent 46%),
radial-gradient(circle at 90% 18%,rgba(129,52,175,.30),transparent 50%),
radial-gradient(circle at 50% 100%,rgba(0,149,246,.26),transparent 55%),#f6f1ff;
background-attachment:fixed}
a{color:inherit;text-decoration:none}
nav{position:fixed;bottom:0;left:50%;transform:translateX(-50%);z-index:5;width:100%;max-width:470px;
box-sizing:border-box;height:calc(var(--nav) + env(safe-area-inset-bottom));padding:0 6px env(safe-area-inset-bottom);
display:flex;justify-content:space-around;align-items:center;font-weight:600;background:rgba(255,255,255,.85);
backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border-top:1px solid rgba(0,0,0,.06);
border-radius:22px 22px 0 0}
h2,h3,h4{margin:4px 4px 14px;font-weight:700;letter-spacing:-.02em}
h3{font-size:20px}
.brand{background:var(--grad);-webkit-background-clip:text;background-clip:text;color:transparent;font-weight:800;font-size:30px;margin:0 0 4px}
.card,.post{background:#fff;border-radius:22px;margin:0 0 28px;overflow:hidden;
box-shadow:0 10px 32px rgba(120,70,170,.13)}
.card{padding:18px}
.flash{background:#fff;border-left:4px solid var(--red);padding:12px 14px;border-radius:12px;margin:0 0 16px;
box-shadow:0 4px 14px rgba(0,0,0,.05)}
small,.mut{color:var(--mut);font-size:12.5px}
.name{font-weight:600}
.bio{margin:6px 8px 10px;color:#444;overflow-wrap:anywhere;white-space:pre-wrap}
.cnt{margin:6px 0 12px;color:#555}
.cnt a{font-weight:500}
.cnt b{font-weight:700;color:var(--ink)}
.shared{padding:14px 16px 0;font-size:13px;color:var(--mut)}
.who{display:flex;align-items:center;gap:12px;padding:14px 16px}
.who small{margin-left:auto}
.tp{display:inline-flex;cursor:pointer}
b.tp,.name.tp{display:inline}
.av{border-radius:50%;object-fit:cover;display:inline-flex;align-items:center;flex:none;
justify-content:center;background:var(--grad);color:#fff;font-weight:600}
.photo{display:block;width:100%;height:auto;max-height:85vh;object-fit:contain;background:#111;border-radius:16px}
.ph{position:relative;touch-action:manipulation;user-select:none;margin:0 12px;border-radius:16px;overflow:hidden}
.burst{position:absolute;left:50%;top:50%;margin:-45px 0 0 -45px;pointer-events:none;opacity:0;
filter:drop-shadow(0 4px 14px rgba(0,0,0,.35))}
.burst svg{fill:#fff;stroke:#fff}
.burst.go{animation:burst .8s ease-out}
@keyframes burst{0%{opacity:0;transform:scale(.4)}25%{opacity:1;transform:scale(1.15)}
60%{opacity:1;transform:scale(1)}100%{opacity:0;transform:scale(1)}}
.playbtn{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);font-size:46px;color:#fff;
text-shadow:0 2px 12px rgba(0,0,0,.5);pointer-events:none}
.ph.playing .playbtn{display:none}
.acts{display:flex;gap:4px;padding:12px 12px 0}
.inl{display:inline}
.ib{background:none;border:0;padding:7px;margin:0;cursor:pointer;color:var(--ink);border-radius:12px;
display:inline-flex;align-items:center}
.ib svg{transition:transform .1s}
.ib:active svg{transform:scale(.85)}
.like.on svg{fill:var(--red);stroke:var(--red)}
.on2{color:#16a34a}
.pop svg{animation:pop .35s ease}
@keyframes pop{0%{transform:scale(1)}40%{transform:scale(1.4)}100%{transform:scale(1)}}
@media (prefers-reduced-motion:reduce){.pop svg,.burst.go{animation:none}}
.lk,.cap,.vc{display:block;padding:6px 16px;font-size:14.5px}
.vc{color:var(--mut);padding-bottom:16px}
.plain{font:inherit;background:none;border:0;cursor:pointer;text-align:left;width:100%;margin:0}
input,textarea{font:inherit;width:100%;box-sizing:border-box;padding:12px 14px;margin:5px 0;
border:1px solid #e4e1ee;border-radius:14px;background:#faf9fd;outline:none}
input:focus,textarea:focus{border-color:#c9a7f0;box-shadow:0 0 0 3px rgba(129,52,175,.12)}
button:not(.ib):not(.plain){font:inherit;font-weight:600;background:var(--grad);color:#fff;border:0;
border-radius:999px;padding:10px 20px;margin:5px 0;cursor:pointer;box-shadow:0 4px 14px rgba(221,42,123,.25)}
button:not(.ib):not(.plain):active{transform:scale(.97)}
.fbtn{padding:7px 16px!important;font-size:13px}
.fbtn.on{background:#efeef5!important;color:var(--ink)!important;box-shadow:none!important}
.cf{display:flex;gap:8px;align-items:center;margin-top:12px}
.cf input{margin:0}
.cf button{flex:none;margin:0}
.c{display:flex;gap:10px;padding:10px 0;align-items:flex-start}
.c .cb{flex:1;min-width:0;overflow-wrap:anywhere;font-size:14px}
.rep{margin-left:38px}
.meta{display:flex;gap:14px;margin-top:3px}
.meta a{color:var(--mut);font-weight:600;font-size:12px}
.cl{display:flex;flex-direction:column;align-items:center;font-size:12px;color:var(--mut);min-width:20px}
.cl .ib{padding:2px}
.avwrap{position:relative;display:inline-block;cursor:pointer}
.plus{position:absolute;right:-2px;bottom:-2px;width:26px;height:26px;border-radius:50%;
background:#0095f6;color:#fff;border:3px solid #fff;display:flex;align-items:center;
justify-content:center;font-size:18px;font-weight:700;line-height:1;cursor:pointer}
.sb{position:relative;margin:0 0 18px}
.sb svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);color:var(--mut)}
.sb input{padding-left:42px;margin:0;background:#fff;border-radius:999px}
.res{display:flex;align-items:center;gap:12px;padding:10px 0}
.grow{flex:1;min-width:0}
.blk{display:block}
.badge{display:inline-block;font-size:11px;font-weight:600;color:#7a3fb0;background:#f1e7fb;border-radius:999px;padding:2px 9px;margin-left:6px}
.tabs{display:flex;gap:6px;margin:0 0 10px;flex-wrap:wrap}
.tab{padding:7px 14px;border-radius:999px;background:#f3f1f8;font-weight:600;font-size:13px;color:#555}
.tab.act{background:var(--grad);color:#fff}
.pw{position:relative}
.pw input{padding-right:46px}
.pw .eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);color:var(--mut)}
.pw .closed{display:none}
.pw.show .open{display:none}
.pw.show .closed{display:inline-flex}
.codein{text-align:center;font-size:26px;letter-spacing:.4em;font-weight:700}
.nv{display:flex;flex-direction:column;align-items:center;gap:2px;flex:1;font-size:10px;font-weight:600;color:var(--mut)}
.nv.act{color:#dd2a7b}
.ring{display:inline-flex;padding:2px;border-radius:50%;background:var(--grad);flex:none}
.ring.seen{background:#c9c9c9}
.ring .av{border:2px solid #fff;box-sizing:content-box}
.tray{display:flex;gap:16px;overflow-x:auto;padding:2px 2px 16px;margin:0 -2px;scrollbar-width:none}
.tray::-webkit-scrollbar{display:none}
.tr{display:flex;flex-direction:column;align-items:center;gap:5px;flex:none;width:70px}
.tr small{max-width:68px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink)}
.pill{display:inline-block;padding:8px 16px;border-radius:999px;background:var(--grad);color:#fff;font-weight:600;font-size:13px;margin:3px}
.pill.alt{background:#efeef5;color:var(--ink)}
.adtag{font-size:11px;font-weight:700;background:#ffe14d;color:#262626;border-radius:999px;padding:2px 9px}
.chk{display:flex;gap:8px;align-items:center;font-size:14px;margin:8px 0}
.chk input{width:auto;margin:0}
.toast{position:fixed;left:50%;bottom:calc(var(--nav) + 18px + env(safe-area-inset-bottom));transform:translateX(-50%);
background:#111;color:#fff;padding:10px 18px;border-radius:999px;font-size:13px;z-index:200;opacity:0;pointer-events:none;transition:opacity .2s}
.toast.on{opacity:1}
.bg0{background:linear-gradient(160deg,#ff5fa2,#7a5cff)}
.bg1{background:linear-gradient(160deg,#00f5a0,#00b4f5)}
.bg2{background:linear-gradient(160deg,#ffe259,#ff8a3d)}
.bg3{background:linear-gradient(160deg,#b388ff,#ffb3e6)}.bg4{background:linear-gradient(160deg,#141e30,#3a6073)}
.bg5{background:linear-gradient(160deg,#f12711,#f5af19)}.bg6{background:linear-gradient(160deg,#ff9a9e,#fad0c4)}
.bg7{background:linear-gradient(160deg,#c6ff00,#00c853)}
/* bottom sheets: comments + profile quick view */
.ov{position:fixed;inset:0;background:rgba(15,10,30,.5);z-index:80;opacity:0;pointer-events:none;transition:opacity .2s}
.ov.open{opacity:1;pointer-events:auto}
#pso{z-index:95}
.sheet{position:fixed;left:50%;bottom:0;width:100%;max-width:470px;transform:translate(-50%,105%);
transition:transform .26s ease;z-index:90;background:#fff;border-radius:26px 26px 0 0;height:72vh;
display:flex;flex-direction:column;box-shadow:0 -12px 44px rgba(0,0,0,.28)}
#ps{z-index:100}
.sheet.open{transform:translate(-50%,0)}
.sh-h{display:flex;justify-content:space-between;align-items:center;padding:16px 18px 8px}
.sh-b{overflow:auto;padding:4px 18px 18px;flex:1}
.sh-f{padding:10px 14px calc(12px + env(safe-area-inset-bottom));border-top:1px solid #f0eef5;margin:0}
.pcard{text-align:center}
.prow{display:flex;gap:6px;justify-content:center;align-items:center;flex-wrap:wrap;margin:6px 0 14px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:6px}
.grid a{display:block;aspect-ratio:1;border-radius:12px;overflow:hidden;background:#eee}
.grid img,.grid video{width:100%;height:100%;object-fit:cover;display:block;pointer-events:none}
</style>
<script>
const $=i=>document.getElementById(i);
const E=s=>String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const HEART='<svg viewBox="0 0 24 24" width=16 height=16 fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/></svg>';
document.addEventListener('submit',e=>{
 const f=e.target; if(!f.classList.contains('ajax'))return;
 e.preventDefault();
 fetch(f.action,{method:'POST',headers:{'X-Requested-With':'fetch'}})
 .then(r=>r.json()).then(d=>{
  const b=f.querySelector('.like'),n=f.closest('article,.c').querySelector('.lc');
  b.classList.toggle('on',d.liked);
  if(d.liked){b.classList.remove('pop');void b.offsetWidth;b.classList.add('pop')}
  n.textContent=n.dataset.noun?d.count+' '+n.dataset.noun+(d.count==1?'':'s'):(d.count||'');
 }).catch(()=>f.submit());
});
let lastTap=0,lastEl=null,tapTimer;
document.addEventListener('click',e=>{
 const ph=e.target.closest('.ph'); if(!ph)return;
 const v=ph.querySelector('video'),now=Date.now();
 if(now-lastTap<300&&lastEl===ph){
  clearTimeout(tapTimer);lastTap=0;
  const f=ph.closest('article').querySelector('form.ajax'),b=ph.querySelector('.burst');
  if(f&&!f.querySelector('.like').classList.contains('on'))f.requestSubmit();
  b.classList.remove('go');void b.offsetWidth;b.classList.add('go');
 }else{
  lastTap=now;lastEl=ph;
  if(v)tapTimer=setTimeout(()=>{v.paused?v.play():v.pause()},300);
 }
});
document.addEventListener('play',e=>{if(e.target.closest)e.target.closest('.ph')?.classList.add('playing')},true);
document.addEventListener('pause',e=>{if(e.target.closest)e.target.closest('.ph')?.classList.remove('playing')},true);
function toast(t){
 let d=$('toast');
 if(!d){d=document.createElement('div');d.id='toast';d.className='toast';document.body.appendChild(d)}
 d.textContent=t;d.classList.add('on');clearTimeout(d.t);d.t=setTimeout(()=>d.classList.remove('on'),2000);
}
document.addEventListener('submit',e=>{
 const f=e.target;if(!f.classList.contains('ajaxs'))return;e.preventDefault();
 fetch(f.action,{method:'POST',headers:{'X-Requested-With':'fetch'}}).then(r=>r.json()).then(d=>{
  if(d.error){toast(d.error);return}
  f.querySelector('button').classList.toggle('on2',d.shared);
  f.closest('.ra').querySelector('.sc').textContent=d.count||'';
  toast(d.shared?'shared to your feed 🔁':'unshared');
 }).catch(()=>f.submit());
});

/* ---------- comments sheet (opens on top of the page, no navigation) ---------- */
const CS={pid:0,parent:null};
function setCc(pid,n){
 document.querySelectorAll('[data-cc="'+pid+'"]').forEach(e=>{
  e.textContent=e.dataset.fmt=='long'?(n?'View all '+n+' comment'+(n==1?'':'s'):'Add a comment'):(n||'');
 });
}
function avHtml(n,a,s){
 return `<span class=tp data-prof="${E(n)}">${a?`<img class=av src="/media/${E(a)}" style="width:${s}px;height:${s}px">`:`<span class=av style="width:${s}px;height:${s}px;font-size:${s/2}px">${E(n[0].toUpperCase())}</span>`}</span>`;
}
function cItem(c,rep){
 return `<div class="c${rep?' rep':''}"><span>${avHtml(c.username,c.avatar,rep?24:32)}</span><div class=cb><b class="name tp" data-prof="${E(c.username)}">${E(c.username)}</b> ${E(c.body)}<div class=meta><small>${E(c.created.slice(0,16))}</small><a href="#" class=crep data-id="${c.id}" data-u="${E(c.username)}">Reply</a></div></div><div class=cl><button type=button class="ib like clk${c.liked?' on':''}" data-id="${c.id}">${HEART}</button><span class=lc>${c.likes||''}</span></div></div>`;
}
function loadComments(){
 fetch('/comments/'+CS.pid+'.json').then(r=>r.json()).then(d=>{
  const list=d.comments,top=list.filter(c=>!c.parent_id);let h='';
  top.forEach(c=>{h+=cItem(c,false);list.filter(r=>r.parent_id==c.id).forEach(r=>{h+=cItem(r,true)})});
  $('cslist').innerHTML=h||'<p class=mut style="text-align:center;padding:30px 0">No comments yet. Start the conversation.</p>';
  setCc(CS.pid,list.length);
 }).catch(()=>{$('cslist').innerHTML='<p class=mut style="text-align:center">Could not load comments.</p>'});
}
function openComments(pid){
 CS.pid=pid;CS.parent=null;$('ci').value='';$('ci').placeholder='Add a comment...';
 $('cslist').innerHTML='<p class=mut style="text-align:center;padding:30px 0">Loading...</p>';
 $('cs').classList.add('open');$('cso').classList.add('open');loadComments();
}
function closeSheets(){
 ['cs','ps'].forEach(i=>{const s=$(i);if(s)s.classList.remove('open')});
 ['cso','pso'].forEach(i=>{const s=$(i);if(s)s.classList.remove('open')});
}
document.addEventListener('submit',e=>{
 if(e.target.id!=='cform')return;e.preventDefault();
 const v=$('ci').value.trim();if(!v)return;
 const fd=new FormData();fd.append('body',v);if(CS.parent)fd.append('parent',CS.parent);
 fetch('/comment/'+CS.pid,{method:'POST',body:fd,headers:{'X-Requested-With':'fetch'}})
 .then(r=>r.json()).then(()=>{$('ci').value='';CS.parent=null;$('ci').placeholder='Add a comment...';loadComments();
  setTimeout(()=>{$('cslist').scrollTop=$('cslist').scrollHeight},250)})
 .catch(()=>toast('could not post comment'));
});

/* ---------- profile quick view (tap a profile picture) ---------- */
function openProfile(n){
 const b=$('psb');b.innerHTML='<p class=mut style="text-align:center;padding:30px">Loading...</p>';
 $('ps').classList.add('open');$('pso').classList.add('open');
 fetch('/api/profile/'+encodeURIComponent(n)).then(r=>r.json()).then(p=>{
  const big=p.avatar?`<img class=av src="/media/${E(p.avatar)}" style="width:88px;height:88px">`:`<span class=av style="width:88px;height:88px;font-size:44px">${E(p.username[0].toUpperCase())}</span>`;
  const u=E(p.username);
  let h=`<div class=pcard>${big}<h3 style="margin:12px 0 2px">@${u}</h3>`;
  if(p.follows_you)h+='<span class=badge style="margin:0">follows you</span>';
  h+=`<p class=bio>${p.bio?E(p.bio):'<span class=mut>No bio yet.</span>'}</p>`;
  h+=`<p class=cnt><b>${p.posts_n}</b> posts · <a href="/u/${u}/followers"><b id=psfc data-u="${u}">${p.followers}</b> followers</a> · <a href="/u/${u}/following"><b>${p.following}</b> following</a></p><div class=prow>`;
  if(!p.is_me)h+=`<button type=button class="fbtn${p.is_following?' on':''}" data-u="${u}">${p.is_following?'Following':'Follow'}</button>`;
  if(p.has_story)h+=`<a class=pill href="/s/${u}">View story</a>`;
  h+=`<a class="pill alt" href="/u/${u}">Full profile</a></div>`;
  if(p.posts.length){
   h+='<div class=grid>'+p.posts.map(x=>`<a href="/p/${x.id}">${x.image?`<img src="/media/${E(x.image)}" loading=lazy>`:`<video src="/media/${E(x.video)}#t=0.1" muted playsinline preload=metadata></video>`}</a>`).join('')+'</div>';
  }else h+='<p class=mut>No posts yet.</p>';
  b.innerHTML=h+'</div>';
 }).catch(()=>{b.innerHTML='<p class=mut style="text-align:center">Could not load this profile.</p>'});
}

document.addEventListener('click',e=>{
 const t=e.target;let x;
 if((x=t.closest('.cbtn'))){e.preventDefault();openComments(x.dataset.pid);return}
 if((x=t.closest('.tp[data-prof]'))){e.preventDefault();openProfile(x.dataset.prof);return}
 if((x=t.closest('.crep'))){e.preventDefault();CS.parent=x.dataset.id;$('ci').value='@'+x.dataset.u+' ';$('ci').focus();return}
 if((x=t.closest('.clk'))){
  fetch('/clike/'+x.dataset.id,{method:'POST',headers:{'X-Requested-With':'fetch'}}).then(r=>r.json()).then(d=>{
   x.classList.toggle('on',d.liked);x.parentElement.querySelector('.lc').textContent=d.count||'';
  });return;
 }
 if((x=t.closest('.fbtn'))){
  e.preventDefault();const n=x.dataset.u;
  fetch('/follow/'+n,{method:'POST',headers:{'X-Requested-With':'fetch'}}).then(r=>r.json()).then(d=>{
   document.querySelectorAll('.fbtn[data-u="'+n+'"]').forEach(b=>{b.textContent=d.following?'Following':'Follow';b.classList.toggle('on',d.following)});
   const fc=$('psfc');if(fc&&fc.dataset.u==n)fc.textContent=d.followers;
   toast(d.following?'following @'+n:'unfollowed @'+n);
  }).catch(()=>toast('something went wrong'));return;
 }
 if(t.id=='cso'||t.id=='pso'||t.id=='csx'||t.id=='psx')closeSheets();
});
document.addEventListener('keydown',e=>{if(e.key=='Escape')closeSheets()});
</script>
{% macro av(name, avatar, size=36, ring=true, tap=true) %}{% set r = rings.get(name) %}{% set hr = ring and r is not none %}<span{% if tap %} class=tp data-prof="{{ name }}"{% endif %}>{% if hr %}<span class="ring{{ '' if r else ' seen' }}">{% endif %}{% if avatar %}<img class=av src="/media/{{ avatar }}" style="width:{{ size }}px;height:{{ size }}px">{% else %}<span class=av style="width:{{ size }}px;height:{{ size }}px;font-size:{{ size // 2 }}px">{{ name[0]|upper }}</span>{% endif %}{% if hr %}</span>{% endif %}</span>{% endmacro %}
{% macro icon(n, s=26) %}<svg viewBox="0 0 24 24" width={{ s }} height={{ s }} fill=none stroke=currentColor stroke-width=2 stroke-linecap=round stroke-linejoin=round>{% if n=='heart' %}<path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"/>{% elif n=='chat' %}<path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/>{% elif n=='eye' %}<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>{% elif n=='eyeoff' %}<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>{% elif n=='search' %}<circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>{% elif n=='home' %}<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>{% elif n=='compass' %}<circle cx="12" cy="12" r="10"/><polygon points="16.24 7.76 14.12 14.12 7.76 16.24 9.88 9.88 16.24 7.76"/>{% elif n=='users' %}<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>{% elif n=='user' %}<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>{% elif n=='logout' %}<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>{% elif n=='film' %}<rect x="2" y="2" width="20" height="20" rx="2.18" ry="2.18"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="17" x2="22" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/>{% elif n=='download' %}<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>{% else %}<polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/>{% endif %}</svg>{% endmacro %}
<nav>
{% if user %}{% set pth = request.path %}
<a class="nv{{ ' act' if pth == '/' }}" href="/">{{ icon('home', 22) }}<span>feed</span></a>
<a class="nv{{ ' act' if pth in ('/reels', '/reel/new') }}" href="/reels">{{ icon('film', 22) }}<span>reels</span></a>
<a class="nv{{ ' act' if pth == '/explore' }}" href="/explore">{{ icon('compass', 22) }}<span>explore</span></a>
<a class="nv{{ ' act' if pth == '/search' }}" href="/search">{{ icon('search', 22) }}<span>search</span></a>
<a class="nv{{ ' act' if pth == '/people' }}" href="/people">{{ icon('users', 22) }}<span>people</span></a>
<a class="nv{{ ' act' if pth == '/u/' + user.username }}" href="/u/{{ user.username }}">{{ icon('user', 22) }}<span>me</span></a>
{% else %}<a href="/login">Log in</a><a href="/register">Sign up</a>{% endif %}
</nav>
{% if user %}
<div class=ov id=cso></div>
<div class=sheet id=cs role=dialog aria-label=Comments>
 <div class=sh-h><b>Comments</b><button type=button class=ib id=csx aria-label=close>✕</button></div>
 <div class=sh-b id=cslist></div>
 <form class="sh-f cf" id=cform autocomplete=off><input id=ci name=body maxlength=300 placeholder="Add a comment..." required><button>Post</button></form>
</div>
<div class=ov id=pso></div>
<div class=sheet id=ps role=dialog aria-label=Profile>
 <div class=sh-h><b>Profile</b><button type=button class=ib id=psx aria-label=close>✕</button></div>
 <div class=sh-b id=psb></div>
</div>
{% endif %}
{% for m in get_flashed_messages() %}<p class=flash>{{ m }}</p>{% endfor %}
"""

AUTH = """<div class="card"><h2 class=brand>Social</h2><h3>{{ title }}</h3>
{% if err %}<p class=flash>{{ err }}</p>{% endif %}
<form method=post>
<input name=username placeholder="{{ 'Username' if mode == 'register' else 'Username or email' }}" required autocomplete=username>
{% if mode == 'register' %}<input name=email type=email placeholder="Email" required maxlength=120 autocomplete=email>{% endif %}
<div class=pw><input name=password type=password placeholder=Password required>
<button type=button class="ib eye" aria-label="Show or hide password" onclick="const w=this.closest('.pw'),i=w.querySelector('input'),s=i.type=='password';i.type=s?'text':'password';w.classList.toggle('show',s)"><span class=open>{{ icon('eye', 20) }}</span><span class=closed>{{ icon('eyeoff', 20) }}</span></button></div>
<button>{{ title }}</button></form>
<p class=mut style="text-align:center;margin-top:14px">{% if mode == 'register' %}Already have an account? <a class=name href="/login">Log in</a>{% else %}New here? <a class=name href="/register">Sign up</a>{% endif %}</p></div>"""

VERIFY = """<div class=card><h3>Check your email 📬</h3>
<p class=mut>We sent a 6-digit code to <b>{{ email }}</b>. Enter it to finish setting up your account. It expires in 10 minutes.</p>
{% if dev %}<p class=mut>Email isn't set up on this server yet, so the code was printed in the server console.</p>{% endif %}
{% if err %}<p class=flash>{{ err }}</p>{% endif %}
<form method=post><input name=code class=codein inputmode=numeric pattern="[0-9]*" maxlength=6 autocomplete=one-time-code placeholder="------" required autofocus>
<button style="width:100%">Verify</button></form>
<form method=post action="/verify/resend"><button class="plain" style="text-align:center;margin-top:10px;color:#8134af;font-weight:600">Resend code</button></form>
<p style="text-align:center"><a class=mut href="/login">Back to login</a></p></div>"""

COMPOSE = """{% if user %}<div class=card><form method=post action="/post" enctype=multipart/form-data id=pf>
<textarea name=body maxlength=500 placeholder="What's on your mind?"></textarea>
<input type=file name=media id=media accept="image/*,video/*">
<input type=hidden name=vx id=vx value=0><input type=hidden name=vy id=vy value=0>
<input type=hidden name=vw id=vw value=1><input type=hidden name=vh id=vh value=1>
<input type=hidden name=vs id=vs value=0><input type=hidden name=vd id=vd value=60>
<img id=cprev class=cprev hidden alt=""><small id=cs class=mut></small>
<button>Post</button></form></div>{% endif %}"""

EDITOR = """{% if user %}<div id=ed hidden>
 <div class=edh><button type=button id=edx>Cancel</button><b>Edit</b><button type=button id=edok>Done</button></div>
 <div class=edst><div id=frame><canvas id=ecv></canvas><video id=evd muted playsinline loop></video></div></div>
 <div class=edc>
  <div class=chips id=asp></div>
  <label><span>Zoom</span><input type=range id=zm min=1 max=4 step=.01 value=1></label>
  <div id=imgc>
   <label><span>Brightness</span><input type=range id=br min=50 max=150 value=100></label>
   <label><span>Contrast</span><input type=range id=ct min=50 max=150 value=100></label>
   <label><span>Saturation</span><input type=range id=sa min=0 max=200 value=100></label>
   <div class=chips><button type=button id=rot>Rotate</button></div>
  </div>
  <div id=vidc hidden>
   <label><span>Start</span><input type=range id=ts min=0 max=60 step=.1 value=0></label>
   <label><span>End</span><input type=range id=te min=0 max=60 step=.1 value=60></label>
   <div class=chips><button type=button id=pp>Play / pause</button><small id=cl></small></div>
  </div>
  <small>Drag the picture to move it. Reels and stories can be 30 seconds, posts 60.</small>
 </div>
</div>

<style>
.cprev{max-height:120px;border-radius:14px;margin:6px 6px 0 0;vertical-align:middle}
#ed{position:fixed;inset:0;z-index:150;background:#111;color:#fff;display:flex;flex-direction:column}
#ed[hidden],#ed [hidden]{display:none!important}
.edh{display:flex;justify-content:space-between;align-items:center;padding:12px 14px}
#ed button{font:inherit;font-weight:600;background:#333;color:#fff;border:0;border-radius:999px;
padding:8px 16px;margin:0;cursor:pointer;box-shadow:none}
#ed button.on{background:#fff;color:#111}
#ed #edok{background:#0095f6}
.edst{flex:none;display:flex;justify-content:center}
#frame{position:relative;overflow:hidden;background:#000;touch-action:none;cursor:grab;border-radius:14px}
#frame canvas,#frame video{position:absolute;display:block;max-width:none;user-select:none}
.edc{flex:1;overflow:auto;padding:12px 14px 28px;display:flex;flex-direction:column;gap:10px;
width:100%;max-width:470px;box-sizing:border-box;margin:0 auto}
.chips{display:flex;gap:6px;flex-wrap:wrap;align-items:center}
#ed label{display:flex;align-items:center;gap:10px;font-size:13px}
#ed label span{width:78px;flex:none}
#ed input[type=range]{padding:0;margin:0;border:0;background:none;flex:1;width:auto;box-shadow:none}
#ed small{color:#aaa}
</style>
<script>
(()=>{
const inp=$('media'),ed=$('ed'),fr=$('frame'),cv=$('ecv'),vd=$('evd'),zm=$('zm'),ts=$('ts'),te=$('te'),
 AS=[['Original',0],['1:1',1],['4:5',.8],['16:9',16/9],['9:16',9/16]],
 mmss=t=>Math.floor(t/60)+':'+String(Math.floor(t%60)).padStart(2,'0'),
 flt=()=>'brightness('+$('br').value+'%) contrast('+$('ct').value+'%) saturate('+$('sa').value+'%)';
const SHORT=!!inp.dataset.short,MAXD=SHORT?30:60;
let m,kind,nw,nh,W,H,ai=SHORT?4:0,ox=0,oy=0,z=1,rot=0,img,url,drag;

$('asp').innerHTML=AS.map((a,i)=>'<button type=button data-i="'+i+'">'+a[0]+'</button>').join('');

function place(center){
 const s=Math.max(W/nw,H/nh)*z,w=nw*s,h=nh*s;
 if(center){ox=(W-w)/2;oy=(H-h)/2}
 ox=Math.min(0,Math.max(W-w,ox));oy=Math.min(0,Math.max(H-h,oy));
 Object.assign(m.style,{width:w+'px',height:h+'px',left:ox+'px',top:oy+'px'});
}
function frame(){
 const a=AS[ai][1]||nw/nh,mw=Math.min(innerWidth,470),mh=innerHeight*.45;
 W=Math.min(mw,mh*a);H=W/a;fr.style.width=W+'px';fr.style.height=H+'px';
 z=1;zm.value=1;place(true);
 [...$('asp').children].forEach((b,i)=>b.classList.toggle('on',i==ai));
}
function draw(){
 const sc=Math.min(1,2000/Math.max(img.naturalWidth,img.naturalHeight)),
  w=Math.round(img.naturalWidth*sc),h=Math.round(img.naturalHeight*sc),q=rot%2;
 cv.width=q?h:w;cv.height=q?w:h;
 const c=cv.getContext('2d');c.translate(cv.width/2,cv.height/2);c.rotate(rot*Math.PI/2);
 c.drawImage(img,-w/2,-h/2,w,h);nw=cv.width;nh=cv.height;
}
function clip(w){
 let a=+ts.value,b=+te.value;
 if(w=='s'){if(b-a<1)b=Math.min(vd.duration,a+1);if(b-a>MAXD)b=a+MAXD}
 if(w=='e'){if(b-a<1)a=Math.max(0,b-1);if(b-a>MAXD)a=b-MAXD}
 ts.value=a;te.value=b;
 $('cl').textContent=mmss(a)+' to '+mmss(b)+' ('+Math.round(b-a)+'s)';
 if(w)vd.currentTime=w=='s'?a:Math.max(a,b-.5);
}
function shut(){ed.hidden=true;vd.pause();document.body.style.overflow='';URL.revokeObjectURL(url)}
function openEd(f){
 const v=f.type.startsWith('video');
 kind=v?'v':'i';rot=0;ai=SHORT?4:0;
 ['br','ct','sa'].forEach(i=>$(i).value=100);cv.style.filter='';
 cv.hidden=v;vd.hidden=!v;$('imgc').hidden=v;$('vidc').hidden=!v;m=v?vd:cv;
 url=URL.createObjectURL(f);ed.hidden=false;document.body.style.overflow='hidden';
 if(v){
  vd.src=url;
  vd.onloadedmetadata=()=>{
   nw=vd.videoWidth;nh=vd.videoHeight;ts.max=te.max=vd.duration;
   ts.value=0;te.value=Math.min(vd.duration,MAXD);vd.currentTime=.01;clip();frame();
  };
 }else{
  img=new Image();img.onload=()=>{draw();frame()};img.src=url;
 }
}

inp.onchange=()=>{
 const f=inp.files[0];$('cprev').hidden=true;$('cs').textContent='';
 if(!f||f.type=='image/gif')return; // GIFs are posted as they are
 if(f.type.startsWith('image')||f.type.startsWith('video'))openEd(f);
};
fr.onpointerdown=e=>{drag=[e.clientX,e.clientY,ox,oy];fr.setPointerCapture(e.pointerId)};
fr.onpointermove=e=>{if(drag){ox=drag[2]+e.clientX-drag[0];oy=drag[3]+e.clientY-drag[1];place()}};
fr.onpointerup=fr.onpointercancel=()=>{drag=null};
zm.oninput=()=>{
 const s0=Math.max(W/nw,H/nh),a=s0*z,cx=(W/2-ox)/(nw*a),cy=(H/2-oy)/(nh*a);
 z=+zm.value;const b=s0*z;ox=W/2-cx*nw*b;oy=H/2-cy*nh*b;place();
};
$('asp').onclick=e=>{const i=e.target.dataset.i;if(i!=null){ai=+i;frame()}};
$('rot').onclick=()=>{rot=(rot+1)%4;draw();frame()};
['br','ct','sa'].forEach(i=>{$(i).oninput=()=>{cv.style.filter=flt()}});
ts.oninput=()=>clip('s');te.oninput=()=>clip('e');
$('pp').onclick=()=>{if(vd.paused)vd.play();else vd.pause()};
vd.ontimeupdate=()=>{if(vd.currentTime>=+te.value)vd.currentTime=+ts.value};
$('edx').onclick=()=>{shut();inp.value='';$('cs').textContent='';$('cprev').hidden=true};
$('edok').onclick=()=>{
 const s=Math.max(W/nw,H/nh)*z;
 if(kind=='v'){
  const set=(i,v)=>{$(i).value=v};
  set('vx',-ox/(nw*s));set('vy',-oy/(nh*s));set('vw',W/(nw*s));set('vh',H/(nh*s));
  set('vs',ts.value);set('vd',te.value-ts.value);
  $('cs').textContent='Video ready: '+$('cl').textContent;shut();return;
 }
 const sw=W/s,sh=H/s,k=Math.min(1,1080/Math.max(sw,sh)),o=document.createElement('canvas');
 o.width=Math.round(sw*k);o.height=Math.round(sh*k);
 const c=o.getContext('2d');c.fillStyle='#fff';c.fillRect(0,0,o.width,o.height);
 c.filter=flt();c.drawImage(cv,-ox/s,-oy/s,sw,sh,0,0,o.width,o.height);
 o.toBlob(b=>{
  const dt=new DataTransfer();dt.items.add(new File([b],'edit.jpg',{type:'image/jpeg'}));inp.files=dt.files;
  const p=$('cprev');p.src=URL.createObjectURL(b);p.hidden=false;$('cs').textContent='Photo ready';shut();
 },'image/jpeg',.9);
};
addEventListener('resize',()=>{if(!ed.hidden&&nw)frame()});
$('pf').onsubmit=()=>{const b=$('pf').querySelector('button:last-of-type');b.disabled=true;b.textContent='Posting...'};
})();
</script>{% endif %}"""
COMPOSE += EDITOR

POSTS = """{% for p in posts %}<article class=post>
{% if p.sharer %}<div class=shared>🔁 <a href="/u/{{ p.sharer }}"><b>{{ p.sharer }}</b></a> shared</div>{% endif %}
<div class=who>{{ av(p.username, p.avatar, 38) }}<a class=name href="/u/{{ p.username }}">{{ p.username }}</a>{% if p.is_ad %}<span class=adtag>sponsored</span>{% endif %}
<small>{{ p.created[:16] }}</small></div>
{% if p.image or p.video %}<div class=ph>
{% if p.video %}<video class=photo src="/media/{{ p.video }}#t=0.1" playsinline loop preload=metadata></video><span class=playbtn>▶</span>
{% else %}<img class=photo src="/media/{{ p.image }}" loading=lazy draggable=false>{% endif %}
<span class=burst>{{ icon('heart', 90) }}</span></div>{% endif %}
<div class=acts>
{% if user %}
<form method=post action="/like/{{ p.id }}" class="inl ajax"><button class="ib like{{ ' on' if p.liked }}">{{ icon('heart') }}</button></form>
<button type=button class="ib cbtn" data-pid="{{ p.id }}" aria-label=comments>{{ icon('chat') }}</button>
<form method=post action="/share/{{ p.id }}" class=inl><button class="ib{{ ' on2' if p.shared }}">{{ icon('repeat') }}</button></form>
{% if p.video and (p.allow_dl or p.username == user.username) %}<a class=ib href="/download/{{ p.id }}" aria-label=download>{{ icon('download') }}</a>{% endif %}
{% else %}<a class=ib href="/login">{{ icon('heart') }}</a><a class=ib href="/p/{{ p.id }}">{{ icon('chat') }}</a>{% endif %}
</div>
<div class=lk><b class=lc data-noun=like>{{ p.likes }} like{{ '' if p.likes == 1 else 's' }}</b>{% if p.shares %} <small>· {{ p.shares }} share{{ '' if p.shares == 1 else 's' }}</small>{% endif %}</div>
{% if p.body %}<div class=cap><b>{{ p.username }}</b> {{ p.body }}</div>{% endif %}
{% if user %}<button type=button class="vc plain cbtn" data-pid="{{ p.id }}" data-cc="{{ p.id }}" data-fmt=long>{% if p.comments %}View all {{ p.comments }} comment{{ '' if p.comments == 1 else 's' }}{% else %}Add a comment{% endif %}</button>
{% else %}<a class=vc href="/p/{{ p.id }}">{% if p.comments %}View all {{ p.comments }} comment{{ '' if p.comments == 1 else 's' }}{% else %}Add a comment{% endif %}</a>{% endif %}
</article>
{% else %}<p class=mut>Nothing here yet.</p>{% endfor %}"""

COMMENTS = """{% macro cmt(c, cls='') %}
<div class="c {{ cls }}" id="c{{ c.id }}">
{{ av(c.username, c.avatar, 24 if cls else 32) }}
<div class=cb><a class=name href="/u/{{ c.username }}">{{ c.username }}</a> {{ c.body }}
<div class=meta><small>{{ c.created[:16] }}</small>
{% if user %}<a href="/p/{{ pid }}?reply={{ c.id }}#c{{ c.id }}">Reply</a>{% endif %}</div>
{% if reply == c.id and user %}<form class=cf method=post action="/comment/{{ pid }}">
<input type=hidden name=parent value="{{ c.id }}">
<input name=body maxlength=300 value="@{{ c.username }} " autofocus required><button>Reply</button></form>{% endif %}
</div>
<div class=cl>
{% if user %}<form method=post action="/clike/{{ c.id }}" class=ajax><button class="ib like{{ ' on' if c.liked }}">{{ icon('heart', 16) }}</button></form>
{% else %}<a class=ib href="/login">{{ icon('heart', 16) }}</a>{% endif %}
<span class=lc>{{ c.likes or '' }}</span></div>
</div>
{% endmacro %}
<div class=card><h4>Comments</h4>
{% for c in comments if not c.parent_id %}{{ cmt(c) }}
{% for r in comments if r.parent_id == c.id %}{{ cmt(r, 'rep') }}{% endfor %}
{% else %}<p class=mut>No comments yet. Start the conversation.</p>{% endfor %}
{% if user %}<form class=cf method=post action="/comment/{{ pid }}">
<input name=body maxlength=300 placeholder="Add a comment..." required><button>Post</button></form>
{% else %}<p><a class=name href="/login">Log in</a> to comment.</p>{% endif %}</div>"""

PEOPLE = """<div class=card><h3>People</h3>
{% for r in rows %}<div class=res>{{ av(r.username, r.avatar, 40) }}<div class=grow><a class=name href="/u/{{ r.username }}">@{{ r.username }}</a>{% if r.bio %}<small class=blk>{{ r.bio[:60] }}</small>{% endif %}</div>
{% if user %}<button type=button class="fbtn{{ ' on' if r.following }}" data-u="{{ r.username }}">{{ 'Following' if r.following else 'Follow' }}</button>{% endif %}</div>
{% else %}<p class=mut>No one else yet.</p>{% endfor %}</div>"""

LIST = """<div class=card><h3><a href="/u/{{ prof.username }}">@{{ prof.username }}</a></h3>
<div class=tabs>
<a class="tab{{ ' act' if kind == 'followers' }}" href="/u/{{ prof.username }}/followers">Followers {{ counts.followers }}</a>
<a class="tab{{ ' act' if kind == 'following' }}" href="/u/{{ prof.username }}/following">Following {{ counts.following }}</a>
<a class="tab{{ ' act' if kind == 'mutual' }}" href="/u/{{ prof.username }}/mutual">Mutual {{ counts.mutual }}</a>
</div>
{% for r in rows %}<div class=res>{{ av(r.username, r.avatar, 44) }}
<div class=grow><a class=name href="/u/{{ r.username }}">@{{ r.username }}</a>{% if r.back %}<span class=badge>{{ 'follows back' if kind == 'following' else 'mutual' }}</span>{% endif %}
{% if r.bio %}<small class=blk>{{ r.bio[:60] }}</small>{% endif %}</div>
{% if r.id != user.id %}<button type=button class="fbtn{{ ' on' if r.me_follows }}" data-u="{{ r.username }}">{{ 'Following' if r.me_follows else 'Follow' }}</button>{% endif %}</div>
{% else %}<p class=mut>Nobody here yet.</p>{% endfor %}</div>"""

SEARCH = """<form method=get action="/search" class=sb>{{ icon('search', 18) }}
<input id=q name=q value="{{ q }}" placeholder="Search people" autocomplete=off autofocus></form>
<div class=card id=res><p class=mut>Search for people by username.</p></div>
<script>
const qi=document.getElementById('q'),box=document.getElementById('res');let t;
function run(){const v=qi.value.trim();
 if(!v){box.innerHTML='<p class=mut>Search for people by username.</p>';return}
 fetch('/search.json?q='+encodeURIComponent(v)).then(r=>r.json()).then(rows=>{
  box.innerHTML=rows.length?rows.map(u=>`<a class=res href="/u/${u.username}">${u.avatar?`<img class=av src="/media/${u.avatar}" style="width:44px;height:44px">`:`<span class=av style="width:44px;height:44px;font-size:22px">${u.username[0].toUpperCase()}</span>`}<span class=name>${u.username}</span></a>`).join(''):'<p class=mut>No people found.</p>'})}
qi.addEventListener('input',()=>{clearTimeout(t);t=setTimeout(run,200)});
if(qi.value)run();
</script>"""

TRAY = """{% if user %}<div class=tray>
<div class=tr><div class=avwrap><a href="/s/{{ user.username }}">{{ av(user.username, user.avatar, 56, true, false) }}</a><a class=plus href="/story/new" aria-label="add to your story">+</a></div><small>your story</small></div>
{% for r in tray %}<a class=tr href="/s/{{ r.username }}">{{ av(r.username, r.avatar, 56, true, false) }}<small>{{ r.username }}</small></a>{% endfor %}
</div>{% if not tray %}<p class=mut style="margin:-4px 4px 18px">stories show up here once you and a friend follow each other 💞</p>{% endif %}{% endif %}"""

REELS = """<style>
.reels{position:fixed;top:0;left:50%;transform:translateX(-50%);width:100%;max-width:470px;
bottom:calc(var(--nav) + env(safe-area-inset-bottom));overflow-y:auto;scroll-snap-type:y mandatory;
background:#000;z-index:2;scrollbar-width:none}
.reels::-webkit-scrollbar{display:none}
.rtop{position:sticky;top:0;height:0;z-index:4}
.rtitle{position:absolute;top:14px;left:14px;color:#fff;font-weight:800;font-size:22px;letter-spacing:-.5px;text-shadow:0 2px 10px rgba(0,0,0,.5)}
.newreel{position:absolute;top:10px;right:12px;background:var(--grad);color:#fff;font-weight:700;font-size:13px;padding:8px 16px;border-radius:999px}
.reel{position:relative;height:100%;scroll-snap-align:start;scroll-snap-stop:always;overflow:hidden;color:#fff;margin:0;border-radius:0;box-shadow:none;background:#000}
.reel::after{content:'';position:absolute;left:0;right:0;bottom:0;height:45%;background:linear-gradient(transparent,rgba(0,0,0,.7));pointer-events:none;z-index:1}
.reel .ph{position:absolute;inset:0;margin:0;border-radius:0}
.rv{display:block;width:100%;height:100%;object-fit:cover;background:#000}
.rside{position:absolute;right:8px;bottom:26px;z-index:3;display:flex;flex-direction:column;align-items:center;gap:12px;font-size:12px;font-weight:700;text-shadow:0 1px 6px rgba(0,0,0,.6)}
.ra{display:flex;flex-direction:column;align-items:center}
.reel .ib{color:#fff;filter:drop-shadow(0 1px 4px rgba(0,0,0,.5))}
.reel .like.on svg{fill:var(--red);stroke:var(--red)}
.reel .on2{color:#4dffa6}
.rinfo{position:absolute;left:14px;right:72px;bottom:26px;z-index:3;text-shadow:0 1px 6px rgba(0,0,0,.6)}
.rinfo p{margin:6px 0 0;font-size:14px;overflow-wrap:anywhere}
.who2{display:flex;align-items:center;gap:8px;margin-top:6px;font-weight:700}
.reel .fbtn{margin:0 0 0 4px;padding:4px 13px!important;font-size:12px;background:transparent!important;border:1.5px solid #fff!important;color:#fff!important;box-shadow:none!important;text-shadow:none}
.reel .fbtn.on{background:rgba(255,255,255,.28)!important;border-color:transparent!important}
.cta{display:inline-block;margin-top:10px;background:#fff;color:#111;font-weight:700;font-size:13px;padding:8px 18px;border-radius:999px;text-shadow:none}
.rbar{position:absolute;left:0;right:0;bottom:0;height:3px;background:rgba(255,255,255,.25);z-index:4}
.rbar b{display:block;height:100%;width:0;background:#fff}
.empty{display:flex;height:100%;align-items:center;justify-content:center;text-align:center;padding:24px;color:#fff;font-weight:700;scroll-snap-align:start}
</style>
<div class=reels>
<div class=rtop><span class=rtitle>reels</span><a class=newreel href="/reel/new">+ new reel</a></div>
{% for p in posts %}<article class=reel>
<div class=ph><video class=rv src="/media/{{ p.video }}" playsinline loop muted preload=metadata></video><span class=playbtn>▶</span><span class=burst>{{ icon('heart', 90) }}</span></div>
<div class=rside>
<div class=ra><form method=post action="/like/{{ p.id }}" class=ajax><button class="ib like{{ ' on' if p.liked }}" aria-label=like>{{ icon('heart', 30) }}</button></form><span class=lc>{{ p.likes or '' }}</span></div>
<div class=ra><button type=button class="ib cbtn" data-pid="{{ p.id }}" aria-label=comments>{{ icon('chat', 30) }}</button><span data-cc="{{ p.id }}" data-fmt=short>{{ p.comments or '' }}</span></div>
<div class=ra><form method=post action="/share/{{ p.id }}" class=ajaxs><button class="ib{{ ' on2' if p.shared }}" aria-label=share>{{ icon('repeat', 30) }}</button></form><span class=sc>{{ p.shares or '' }}</span></div>
{% if p.allow_dl or p.username == user.username %}<div class=ra><a class=ib href="/download/{{ p.id }}" aria-label=download>{{ icon('download', 28) }}</a><span>save</span></div>{% endif %}
<button type=button class="ib mute" aria-label="sound on or off">🔇</button>
</div>
<div class=rinfo>{% if p.is_ad %}<span class=adtag>sponsored</span>{% endif %}
<div class=who2>{{ av(p.username, p.avatar, 36) }}<a href="/u/{{ p.username }}">{{ p.username }}</a>{% if p.owner_id != user.id %}<button type=button class="fbtn{{ ' on' if p.following }}" data-u="{{ p.username }}">{{ 'Following' if p.following else 'Follow' }}</button>{% endif %}</div>
{% if p.body %}<p>{{ p.body }}</p>{% endif %}
{% if p.is_ad and p.ad_url %}<a class=cta href="{{ p.ad_url }}" target=_blank rel="noopener nofollow">learn more</a>{% endif %}
</div><i class=rbar><b></b></i></article>
{% else %}<div class=empty>no reels yet. be the first to post one 🎬</div>{% endfor %}
</div>
<script>
(()=>{
const box=document.querySelector('.reels');let muted=true,cur=null;const pos=new WeakMap();
box.querySelectorAll('.reel video').forEach(v=>{
 const bar=v.closest('.reel').querySelector('.rbar b');
 v.addEventListener('timeupdate',()=>{if(v.duration)bar.style.width=(v.currentTime/v.duration*100)+'%'});
});
function go(v){
 v.muted=muted;
 const p=v.play();
 if(p)p.catch(()=>{v.muted=true;v.play().catch(()=>{})});
}
// the reel in view plays automatically; the one you scrolled away from pauses and
// picks up where you left off when you come back. Reels loop like on TikTok.
const io=new IntersectionObserver(es=>es.forEach(e=>{
 const v=e.target.querySelector('video');
 if(e.isIntersecting){
  cur=v;const t=pos.get(v);if(t){try{v.currentTime=t}catch(_){}}
  go(v);
  const nx=e.target.nextElementSibling,nv=nx&&nx.querySelector('video');if(nv)nv.preload='auto';
 }else{pos.set(v,v.currentTime);v.pause()}
}),{root:box,threshold:.6});
box.querySelectorAll('.reel').forEach(r=>io.observe(r));
box.addEventListener('click',e=>{
 if(!e.target.closest('.mute'))return;
 muted=!muted;box.querySelectorAll('video').forEach(v=>{v.muted=muted});
 box.querySelectorAll('.mute').forEach(x=>{x.textContent=muted?'🔇':'🔊'});
 if(cur&&cur.paused)go(cur);
});
document.addEventListener('visibilitychange',()=>{if(!cur)return;if(document.hidden)cur.pause();else go(cur)});
})();
</script>"""

REEL_NEW = """<div class=card><h3>new reel 🎬</h3>
<form method=post action="/reel" enctype=multipart/form-data id=pf>
<input type=file name=media id=media accept="video/*" data-short=1 required>
<textarea name=body maxlength=200 placeholder="caption it..."></textarea>
<input type=hidden name=vx id=vx value=0><input type=hidden name=vy id=vy value=0>
<input type=hidden name=vw id=vw value=1><input type=hidden name=vh id=vh value=1>
<input type=hidden name=vs id=vs value=0><input type=hidden name=vd id=vd value=30>
<label class=chk><input type=checkbox name=allow_dl value=1> let people download this reel</label>
<label class=chk><input type=checkbox name=is_ad value=1 onchange="document.getElementById('adu').hidden=!this.checked"> this reel is an ad (adds a sponsored tag)</label>
<input name=ad_url id=adu type=url maxlength=300 placeholder="link people can tap (https://...)" hidden>
<img id=cprev class=cprev hidden alt=""><small id=cs class=mut></small>
<small class=mut style="display:block">short videos only: up to 30 seconds.</small>
<button>post reel</button></form></div>"""

STORY_NEW = """<div class=card><h3>add to your story ✨</h3>
<form method=post action="/story" enctype=multipart/form-data id=pf>
<div class="stcard bg0" id=stc><textarea name=body maxlength=280 placeholder="what's the vibe rn?"></textarea></div>
<div class=sw>{% for i in range(8) %}<label><input type=radio name=bg value="{{ i }}"{{ ' checked' if i == 0 }}><span class="bg{{ i }}"></span></label>{% endfor %}</div>
<input type=file name=media id=media accept="image/*,video/*" data-short=1>
<input type=hidden name=vx id=vx value=0><input type=hidden name=vy id=vy value=0>
<input type=hidden name=vw id=vw value=1><input type=hidden name=vh id=vh value=1>
<input type=hidden name=vs id=vs value=0><input type=hidden name=vd id=vd value=30>
<img id=cprev class=cprev hidden alt=""><small id=cs class=mut></small>
<small class=mut style="display:block">add a photo or video if you want. only people you follow each other with can see it, gone in 24h 💨</small>
<button>share to story</button></form></div>
<style>
.stcard{aspect-ratio:3/4;border-radius:22px;display:flex;align-items:center;justify-content:center;padding:18px;margin-bottom:12px}
.stcard textarea{background:transparent;border:0;color:#fff;font-size:28px;font-weight:800;text-align:center;resize:none;height:100%;outline:none;line-height:1.15;letter-spacing:-.5px;box-shadow:none}
.stcard textarea::placeholder{color:rgba(255,255,255,.7)}
.sw{display:flex;gap:10px;margin:4px 0 12px;flex-wrap:wrap}
.sw label{cursor:pointer}
.sw input{display:none}
.sw span{display:block;width:34px;height:34px;border-radius:50%}
.sw input:checked+span{box-shadow:0 0 0 3px #fff,0 0 0 5px #262626}
</style>
<script>
document.querySelectorAll('.sw input').forEach(r=>{r.onchange=()=>{document.getElementById('stc').className='stcard bg'+r.value}});
</script>"""

STORY_VIEW = """<style>
#sv{position:fixed;inset:0;z-index:60;background:#000;color:#fff;max-width:470px;margin:0 auto;overflow:hidden}
#stage{position:absolute;inset:0;display:flex;align-items:center;justify-content:center}
#stage img,#stage video{width:100%;height:100%;object-fit:contain;background:#000}
.cap2{position:absolute;left:16px;right:16px;bottom:170px;text-align:center;font-size:16px;margin:0;text-shadow:0 1px 8px rgba(0,0,0,.7);overflow-wrap:anywhere}
.cap2.big{position:static;font-size:32px;font-weight:800;line-height:1.12;padding:0 24px;letter-spacing:-.8px;text-shadow:none}
.svtop{position:absolute;left:0;right:0;top:0;z-index:3;padding:calc(10px + env(safe-area-inset-top)) 12px 24px;background:linear-gradient(rgba(0,0,0,.5),transparent)}
#bars{display:flex;gap:4px}
#bars i{flex:1;height:3px;border-radius:3px;background:rgba(255,255,255,.35);overflow:hidden}
#bars b{display:block;height:100%;width:0;background:#fff}
.svhead{display:flex;align-items:center;gap:10px;margin-top:10px}
.svhead small{color:rgba(255,255,255,.75)}
.svx{font-size:22px;padding:4px 6px}
#zl,#zr{position:absolute;top:90px;bottom:150px;z-index:2}
#zl{left:0;width:35%}
#zr{right:0;width:65%}
.svfoot{position:absolute;left:0;right:0;bottom:0;z-index:3;padding:30px 12px calc(12px + env(safe-area-inset-bottom));background:linear-gradient(transparent,rgba(0,0,0,.65))}
#sv button{font:inherit;background:none;border:0;color:#fff;padding:6px;margin:0;cursor:pointer;border-radius:0;box-shadow:none}
#emo{display:flex;justify-content:space-around;margin-bottom:6px}
#emo button{font-size:28px}
.svrow{display:flex;gap:8px;align-items:center}
#sv input{background:rgba(255,255,255,.16);border:1px solid rgba(255,255,255,.4);color:#fff;border-radius:999px;margin:0;padding:11px 16px}
#sv input::placeholder{color:rgba(255,255,255,.7)}
#rs{font-weight:700}
#lk.on svg{fill:var(--red);stroke:var(--red)}
#stats{font-weight:700;font-size:15px}
#rep{max-height:30vh;overflow:auto;font-size:14px;padding:8px 6px;line-height:1.5}
#rep[hidden]{display:none}
.fl{position:absolute;bottom:130px;font-size:34px;z-index:4;pointer-events:none;animation:flo 1.1s ease-out forwards}
@keyframes flo{to{transform:translateY(-220px) scale(1.4);opacity:0}}
</style>
<div id=sv>
<div class=svtop><div id=bars></div>
<div class=svhead>{{ av(owner.username, owner.avatar, 34, false, false) }}<b>{{ owner.username }}</b><small id=ago></small><span style="flex:1"></span>
<button type=button id=snd hidden aria-label="sound on or off">🔇</button>{% if mine %}<button type=button id=del aria-label="delete story">🗑</button>{% endif %}<a class=svx href="/" aria-label=close>✕</a></div></div>
<div id=stage></div><div id=zl></div><div id=zr></div>
<div class=svfoot>
{% if mine %}<button type=button id=stats></button><div id=rep hidden></div>
{% else %}<div id=emo>{% for e in ['🔥','😭','💀','😍','🥺'] %}<button type=button data-e="{{ e }}">{{ e }}</button>{% endfor %}</div>
<div class=svrow><input id=rt placeholder="drop a vibe..." maxlength=200 autocomplete=off><button type=button id=rs>send</button><button type=button id=lk aria-label=like>{{ icon('heart', 26) }}</button></div>{% endif %}
</div></div>
<script>
(()=>{
const S={{ stories|tojson }},MINE={{ 'true' if mine else 'false' }};
const stage=$('stage'),bars=$('bars');
let i=0,timer,vid,held=false;
bars.innerHTML=S.map(()=>'<i><b></b></i>').join('');
const ago=c=>{const m=Math.max(1,Math.round((Date.now()-new Date(c.replace(' ','T')+'Z'))/60000));return m<60?m+'m':Math.floor(m/60)+'h'};
function run(d){
 const f=bars.children[i].firstChild;void f.offsetWidth; f.style.transition='width '+d+'ms linear';f.style.width='100%';
 clearTimeout(timer);timer=setTimeout(()=>show(i+1),d);
}
function hold(){
 if(held)return;held=true;clearTimeout(timer);
 const f=bars.children[i].firstChild,w=getComputedStyle(f).width;
 f.style.transition='none';f.style.width=w;if(vid)vid.pause();
}
function release(){
 if(!held)return;held=false;
 const f=bars.children[i].firstChild;void f.offsetWidth; f.style.transition='width 4s linear';f.style.width='100%';
 clearTimeout(timer);timer=setTimeout(()=>show(i+1),4000);if(vid)vid.play();
}
function floaty(em){
 const f=document.createElement('span');f.className='fl';f.textContent=em;
 f.style.left=(15+Math.random()*65)+'%';$('sv').appendChild(f);setTimeout(()=>f.remove(),1100);
}
function fillReplies(s){
 const r=$('rep');r.textContent='';r.hidden=true;
 s.replies.forEach(x=>{
  const d=document.createElement('div'),b=document.createElement('b');
  b.textContent=x.username+' ';d.appendChild(b);d.appendChild(document.createTextNode(x.body));r.appendChild(d);
 });
 if(!s.replies.length)r.textContent='no replies yet';
}
function show(n){
 clearTimeout(timer);held=false;if(vid){vid.pause();vid=null}
 if(n>=S.length){location.href='/';return}
 i=Math.max(0,n);const s=S[i];
 [...bars.children].forEach((b,k)=>{const f=b.firstChild;f.style.transition='none';f.style.width=k<i?'100%':'0'});
 stage.className=s.kind=='text'?'bg'+s.bg:'';stage.textContent='';
 if(s.kind!='text'){
  const e=document.createElement(s.kind=='photo'?'img':'video');e.src='/media/'+s.media;
  if(s.kind=='video'){e.muted=true;e.playsInline=true;e.autoplay=true;vid=e}
  stage.appendChild(e);
 }
 if(s.body){
  const p=document.createElement('p');p.className='cap2'+(s.kind=='text'?' big':'');
  p.textContent=s.body;stage.appendChild(p);
 }
 $('ago').textContent=ago(s.created);$('snd').hidden=!vid;$('snd').textContent='🔇';
 if(vid)vid.onloadedmetadata=()=>run(Math.min(vid.duration||5,30)*1000);else run(5000);
 if(MINE){$('stats').textContent='👁 '+s.views+'   ♥ '+s.likes+'   💬 '+s.replies.length;fillReplies(s)}
 else{$('lk').classList.toggle('on',!!s.liked);fetch('/sview/'+s.id,{method:'POST'})}
}
$('zl').onclick=()=>show(i-1);$('zr').onclick=()=>show(i+1);
$('snd').onclick=()=>{if(vid){vid.muted=!vid.muted;$('snd').textContent=vid.muted?'🔇':'🔊'}};
if(MINE){
 $('stats').onclick=()=>{const r=$('rep');r.hidden=!r.hidden;if(r.hidden)release();else hold()};
 $('del').onclick=()=>{if(confirm('delete this story?'))fetch('/sdel/'+S[i].id,{method:'POST'}).then(()=>{location.href='/'})};
}else{
 const send=fd=>fetch('/sreply/'+S[i].id,{method:'POST',body:fd}).then(r=>r.json());
 $('emo').onclick=e=>{
  const b=e.target.closest('button');if(!b)return;
  const fd=new FormData();fd.append('emoji',b.dataset.e);
  send(fd).then(()=>toast('sent '+b.dataset.e));floaty(b.dataset.e);
 };
 const sendText=()=>{
  const v=$('rt').value.trim();if(!v)return;
  const fd=new FormData();fd.append('body',v);
  send(fd).then(()=>{$('rt').value='';$('rt').blur();toast('sent 💌')});
 };
 $('rs').onclick=sendText;
 $('rt').onkeydown=e=>{if(e.key=='Enter')sendText()};$('rt').onfocus=hold;$('rt').onblur=release;
 $('lk').onclick=()=>{
  fetch('/slike/'+S[i].id,{method:'POST',headers:{'X-Requested-With':'fetch'}}).then(r=>r.json()).then(d=>{
   S[i].liked=d.liked;$('lk').classList.toggle('on',d.liked);if(d.liked)floaty('❤️');
  });
 };
}
show(0);
})();
</script>"""

PROFILE = """<div class=card style="text-align:center">{% if user and user.id == prof.id %}<form method=post action="/avatar" enctype=multipart/form-data>
<div class=avwrap>{{ av(prof.username, prof.avatar, 92, true, false) }}<label class=plus title="Change profile photo">+<input type=file name=image accept="image/*" hidden onchange="this.form.submit()"></label></div></form>{% else %}{{ av(prof.username, prof.avatar, 92, true, false) }}{% endif %}
<h2 style="margin-top:12px">@{{ prof.username }}</h2>
{% if user and user.id != prof.id and follows_back %}<span class=badge style="margin:0 0 6px">follows you</span>{% endif %}
{% if prof.bio %}<p class=bio>{{ prof.bio }}</p>{% endif %}
<p class=cnt><a href="/u/{{ prof.username }}/followers"><b>{{ followers }}</b> followers</a> · <a href="/u/{{ prof.username }}/following"><b>{{ following }}</b> following</a> · <a href="/u/{{ prof.username }}/mutual"><b>{{ mutual_n }}</b> mutual</a></p>
{% if user and user.id == prof.id %}
<form method=post action="/bio"><textarea name=bio maxlength=150 rows=2 placeholder="Write a short bio...">{{ prof.bio or '' }}</textarea><button>Save bio</button></form>
<p><a class=pill href="/story/new">+ add to your story</a><a class=pill href="/reel/new">+ new reel</a></p>
<p><a class=mut href="/logout">log out</a></p>
{% elif user %}<form method=post action="/follow/{{ prof.username }}">
<button>{{ 'Unfollow' if is_following else 'Follow' }}</button></form>
{% if not mutual %}<p><small class=mut>follow each other to see their stories 👀</small></p>{% endif %}{% endif %}
</div>"""

# ---------- stories: who can see what ----------
# A story is visible to its author and to people who follow each other with the author.
MUTUAL = (
    "(s.user_id=:me OR (EXISTS(SELECT 1 FROM follows a WHERE a.follower=:me AND a.followed=s.user_id)"
    " AND EXISTS(SELECT 1 FROM follows b WHERE b.follower=s.user_id AND b.followed=:me)))"
)
LIVE = "s.created > datetime('now','-1 day')"  # stories last 24 hours


def story_rows(me_id):
    """One row per person with a live story the viewer can see (drives rings + the tray)."""
    return db().execute(
        f"""SELECT u.username, u.avatar,
            MIN(CASE WHEN s.user_id=:me THEN 0 WHEN sv.user_id IS NULL THEN 0 ELSE 1 END) AS seen,
            MAX(s.id) AS last
            FROM stories s JOIN users u ON u.id=s.user_id
            LEFT JOIN story_views sv ON sv.story_id=s.id AND sv.user_id=:me
            WHERE {LIVE} AND {MUTUAL}
            GROUP BY u.id ORDER BY seen, last DESC""",
        {"me": me_id},
    ).fetchall()


def visible_stories(me_id, username):
    return db().execute(
        f"""SELECT s.id, s.user_id, s.kind, s.media, s.body, s.bg, s.created,
            u.username, u.avatar,
            EXISTS(SELECT 1 FROM story_likes l WHERE l.story_id=s.id AND l.user_id=:me) AS liked,
            (SELECT COUNT(*) FROM story_likes l WHERE l.story_id=s.id) AS likes,
            (SELECT COUNT(*) FROM story_views v WHERE v.story_id=s.id) AS views
            FROM stories s JOIN users u ON u.id=s.user_id
            WHERE u.username=:name AND {LIVE} AND {MUTUAL} ORDER BY s.id""",
        {"me": me_id, "name": username},
    ).fetchall()


def story_for(sid):
    """A live story the current user is allowed to see, else 404."""
    row = db().execute(
        f"SELECT s.* FROM stories s WHERE s.id=:sid AND {LIVE} AND {MUTUAL}",
        {"sid": sid, "me": session["uid"]},
    ).fetchone()
    if not row:
        abort(404)
    return row


def page(body, **ctx):
    me = current_user()
    rows = story_rows(me["id"]) if me else []
    rings = {r["username"]: not r["seen"] for r in rows}  # True = unseen story, False = all seen
    tray = [r for r in rows if r["username"] != me["username"]] if me else []
    return render_template_string(BASE + body, user=me, rings=rings, tray=tray, **ctx)


# ---------- auth ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    err = None
    if request.method == "POST":
        name = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        if not name.isalnum() or len(name) > 20 or len(pw) < 8:
            err = "Username: letters/numbers only (max 20). Password: 8+ characters."
        elif not EMAIL_RE.match(email) or len(email) > 120:
            err = "Please enter a valid email address."
        else:
            d = db()
            # a signup that was never verified shouldn't block the name or email forever
            d.execute("DELETE FROM users WHERE verified=0 AND (username=? OR email=?)", (name, email))
            if d.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
                err = "That email already has an account. Try logging in."
            else:
                try:
                    cur = d.execute(
                        "INSERT INTO users(username,password,email,verified) VALUES(?,?,?,0)",
                        (name, generate_password_hash(pw), email),
                    )
                    d.commit()
                except sqlite3.IntegrityError:
                    err = "Username taken."
                else:
                    session.clear()
                    session["pending"] = cur.lastrowid
                    issue_code(cur.lastrowid, email)
                    return redirect("/verify")
    return page(AUTH, title="Sign up", mode="register", err=err)


@app.route("/login", methods=["GET", "POST"])
def login():
    err = None
    if request.method == "POST":
        ident = request.form.get("username", "").strip().lower()
        u = db().execute(
            "SELECT * FROM users WHERE username=? OR email=?", (ident, ident)
        ).fetchone()
        if u and check_password_hash(u["password"], request.form.get("password", "")):
            session.clear()
            if not u["verified"]:  # signed up but never entered the code
                session["pending"] = u["id"]
                issue_code(u["id"], u["email"])
                flash("Please verify your email first. We sent you a new code.")
                return redirect("/verify")
            session["uid"] = u["id"]
            return redirect("/")
        err = "Wrong username/email or password."
    return page(AUTH, title="Log in", mode="login", err=err)


@app.route("/verify", methods=["GET", "POST"])
def verify():
    uid = session.get("pending")
    if not uid:
        return redirect("/login")
    u = db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        session.clear()
        return redirect("/login")
    if u["verified"]:
        session.clear()
        session["uid"] = u["id"]
        return redirect("/")
    err = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        row = db().execute("SELECT * FROM email_codes WHERE user_id=?", (uid,)).fetchone()
        if not row or row["expires"] < time.time():
            err = "That code expired. Tap resend for a new one."
        elif row["attempts"] >= 5:
            err = "Too many tries. Tap resend for a new code."
        elif hmac.compare_digest(row["code_hash"], hash_code(uid, code)):
            db().execute("UPDATE users SET verified=1 WHERE id=?", (uid,))
            db().execute("DELETE FROM email_codes WHERE user_id=?", (uid,))
            db().commit()
            session.clear()
            session["uid"] = uid
            flash("Email verified. Welcome! 🎉")
            return redirect("/")
        else:
            db().execute("UPDATE email_codes SET attempts=attempts+1 WHERE user_id=?", (uid,))
            db().commit()
            err = "Wrong code."
    return page(VERIFY, err=err, email=mask_email(u["email"]), dev=not SMTP_HOST)


@app.route("/verify/resend", methods=["POST"])
def resend_code():
    uid = session.get("pending")
    if not uid:
        return redirect("/login")
    u = db().execute("SELECT * FROM users WHERE id=? AND verified=0", (uid,)).fetchone()
    if not u:
        return redirect("/login")
    row = db().execute("SELECT sent FROM email_codes WHERE user_id=?", (uid,)).fetchone()
    if row and time.time() - row["sent"] < RESEND_WAIT:
        flash(f"Please wait {RESEND_WAIT} seconds before asking for another code.")
    else:
        issue_code(uid, u["email"])
        flash("New code sent.")
    return redirect("/verify")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ---------- feed, posts ----------
@app.route("/")
def feed():
    me = current_user()
    posts = fetch_posts(
        "WHERE p.user_id=? OR p.user_id IN (SELECT followed FROM follows WHERE follower=?)",
        (me["id"], me["id"]),
        me["id"],
    )
    return page(TRAY + COMPOSE + "<h3>Your feed</h3>" + POSTS, posts=posts)


@app.route("/explore")
def explore():
    me = current_user()
    posts = fetch_posts(where="WHERE p.repost_of IS NULL AND p.is_reel=0", uid=me["id"])
    return page(COMPOSE + "<h3>Explore</h3>" + POSTS, posts=posts)


@app.route("/post", methods=["POST"])
@login_required
def new_post():
    body = request.form.get("body", "").strip()[:500]
    f = request.files.get("media")
    img = vid = None
    if f and f.filename:
        img = save_image(f)
        if not img:
            vid = save_video(f)
        if not (img or vid):
            flash("Couldn't use that file. Use a JPG, PNG, GIF or WebP image, or an MP4, MOV or WebM video.")
            return redirect("/")
        if vid and not FFMPEG:
            flash("Video posted without cropping or trimming. In Termux run: pkg install ffmpeg")
    if body or img or vid:
        db().execute(
            "INSERT INTO posts(user_id,body,image,video) VALUES(?,?,?,?)",
            (session["uid"], body, img, vid),
        )
        db().commit()
    return redirect("/")


@app.route("/p/<int:pid>")
def post_page(pid):
    me = current_user()
    uid = me["id"]
    posts = fetch_posts("WHERE p.id=? AND p.repost_of IS NULL", (pid,), uid)
    if not posts:
        abort(404)
    return page(
        POSTS + COMMENTS, posts=posts, comments=comment_rows(pid, uid), pid=pid,
        reply=request.args.get("reply", type=int),
    )


def original_post(pid):
    row = db().execute("SELECT * FROM posts WHERE id=? AND repost_of IS NULL", (pid,)).fetchone()
    if not row:
        abort(404)
    return row


def toggle_like(table, col, target):
    """Like/unlike a post or comment. Returns JSON for the page's JS, else redirects."""
    d, uid = db(), session["uid"]
    was = d.execute(
        f"SELECT 1 FROM {table} WHERE user_id=? AND {col}=?", (uid, target)
    ).fetchone()
    if was:
        d.execute(f"DELETE FROM {table} WHERE user_id=? AND {col}=?", (uid, target))
    else:
        d.execute(f"INSERT INTO {table}(user_id,{col}) VALUES(?,?)", (uid, target))
    d.commit()
    if request.headers.get("X-Requested-With") == "fetch":
        n = d.execute(f"SELECT COUNT(*) FROM {table} WHERE {col}=?", (target,)).fetchone()[0]
        return jsonify(liked=not was, count=n)
    return redirect(request.referrer or "/")


@app.route("/like/<int:pid>", methods=["POST"])
@login_required
def like(pid):
    original_post(pid)
    return toggle_like("likes", "post_id", pid)


@app.route("/clike/<int:cid>", methods=["POST"])
@login_required
def comment_like(cid):
    if not db().execute("SELECT 1 FROM comments WHERE id=?", (cid,)).fetchone():
        abort(404)
    return toggle_like("comment_likes", "comment_id", cid)


@app.route("/comments/<int:pid>.json")
def comments_json(pid):
    """Feeds the comment sheet that slides up over the feed and reels."""
    original_post(pid)
    return jsonify(comments=[dict(r) for r in comment_rows(pid, session["uid"])])


@app.route("/comment/<int:pid>", methods=["POST"])
@login_required
def comment(pid):
    original_post(pid)
    body = request.form.get("body", "").strip()[:300]
    parent = request.form.get("parent", type=int)
    if parent:  # replies to replies attach to the top-level comment, like Instagram
        row = db().execute(
            "SELECT id, parent_id FROM comments WHERE id=? AND post_id=?", (parent, pid)
        ).fetchone()
        parent = (row["parent_id"] or row["id"]) if row else None
    if body:
        db().execute(
            "INSERT INTO comments(post_id,user_id,body,parent_id) VALUES(?,?,?,?)",
            (pid, session["uid"], body, parent),
        )
        db().commit()
    if request.headers.get("X-Requested-With") == "fetch":
        n = db().execute("SELECT COUNT(*) FROM comments WHERE post_id=?", (pid,)).fetchone()[0]
        return jsonify(ok=True, count=n)
    return redirect(f"/p/{pid}")


@app.route("/share/<int:pid>", methods=["POST"])
@login_required
def share(pid):
    orig = original_post(pid)
    d, uid = db(), session["uid"]
    ajax = request.headers.get("X-Requested-With") == "fetch"
    if orig["user_id"] == uid:
        if ajax:
            return jsonify(error="you can't share your own post")
        flash("You can't share your own post.")
        return redirect(request.referrer or "/")
    existing = d.execute(
        "SELECT id FROM posts WHERE user_id=? AND repost_of=?", (uid, pid)
    ).fetchone()
    if existing:
        d.execute("DELETE FROM posts WHERE id=?", (existing["id"],))
    else:
        d.execute("INSERT INTO posts(user_id,body,repost_of) VALUES(?,?,?)", (uid, "", pid))
    d.commit()
    if ajax:
        n = d.execute("SELECT COUNT(*) FROM posts WHERE repost_of=?", (pid,)).fetchone()[0]
        return jsonify(shared=not existing, count=n)
    return redirect(request.referrer or "/")


# ---------- profiles, follow, people ----------
def count_follows(uid):
    d = db()
    followers = d.execute("SELECT COUNT(*) FROM follows WHERE followed=?", (uid,)).fetchone()[0]
    following = d.execute("SELECT COUNT(*) FROM follows WHERE follower=?", (uid,)).fetchone()[0]
    mutual = d.execute(
        """SELECT COUNT(*) FROM follows a JOIN follows b
           ON a.follower=b.followed AND a.followed=b.follower WHERE a.follower=?""",
        (uid,),
    ).fetchone()[0]
    return {"followers": followers, "following": following, "mutual": mutual}


def follows(a, b):
    return bool(db().execute(
        "SELECT 1 FROM follows WHERE follower=? AND followed=?", (a, b)
    ).fetchone())


@app.route("/u/<name>")
def profile(name):
    d, me = db(), current_user()
    prof = d.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
    if not prof:
        abort(404)
    c = count_follows(prof["id"])
    is_following = follows(me["id"], prof["id"])
    follows_back = follows(prof["id"], me["id"])
    posts = fetch_posts("WHERE p.user_id=?", (prof["id"],), me["id"])
    return page(
        PROFILE + POSTS,
        prof=prof, posts=posts, followers=c["followers"], following=c["following"], mutual_n=c["mutual"],
        is_following=is_following, follows_back=follows_back,
        mutual=is_following and follows_back,
    )


def follow_list(prof_id, kind, me_id):
    """People in a followers / following / mutual list, with 'follows back' info."""
    if kind == "followers":
        join = "JOIN follows f ON f.follower=u.id AND f.followed=:p"
        back = "EXISTS(SELECT 1 FROM follows x WHERE x.follower=:p AND x.followed=u.id)"
    elif kind == "following":
        join = "JOIN follows f ON f.followed=u.id AND f.follower=:p"
        back = "EXISTS(SELECT 1 FROM follows x WHERE x.follower=u.id AND x.followed=:p)"
    else:
        join = ("JOIN follows f ON f.follower=u.id AND f.followed=:p "
                "JOIN follows g ON g.followed=u.id AND g.follower=:p")
        back = "1"
    return db().execute(
        f"""SELECT u.id, u.username, u.avatar, u.bio, {back} AS back,
            EXISTS(SELECT 1 FROM follows y WHERE y.follower=:me AND y.followed=u.id) AS me_follows
            FROM users u {join} ORDER BY u.username LIMIT 200""",
        {"p": prof_id, "me": me_id},
    ).fetchall()


@app.route("/u/<name>/<kind>")
def follow_lists(name, kind):
    if kind not in ("followers", "following", "mutual"):
        abort(404)
    me = current_user()
    prof = db().execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
    if not prof:
        abort(404)
    return page(
        LIST, prof=prof, kind=kind, counts=count_follows(prof["id"]),
        rows=follow_list(prof["id"], kind, me["id"]),
    )


@app.route("/api/profile/<name>")
def api_profile(name):
    """Data for the profile quick-view that opens when you tap a profile picture."""
    d, me = db(), current_user()
    prof = d.execute("SELECT * FROM users WHERE username=?", (name,)).fetchone()
    if not prof:
        abort(404)
    c = count_follows(prof["id"])
    posts = d.execute(
        """SELECT id, image, video FROM posts
           WHERE user_id=? AND repost_of IS NULL AND (image IS NOT NULL OR video IS NOT NULL)
           ORDER BY id DESC LIMIT 9""",
        (prof["id"],),
    ).fetchall()
    posts_n = d.execute(
        "SELECT COUNT(*) FROM posts WHERE user_id=? AND repost_of IS NULL", (prof["id"],)
    ).fetchone()[0]
    return jsonify(
        username=prof["username"], avatar=prof["avatar"], bio=prof["bio"] or "",
        followers=c["followers"], following=c["following"], posts_n=posts_n,
        is_me=prof["id"] == me["id"],
        is_following=follows(me["id"], prof["id"]),
        follows_you=follows(prof["id"], me["id"]),
        has_story=bool(visible_stories(me["id"], prof["username"])),
        posts=[dict(r) for r in posts],
    )


@app.route("/bio", methods=["POST"])
@login_required
def set_bio():
    bio = request.form.get("bio", "").strip()[:150]
    db().execute("UPDATE users SET bio=? WHERE id=?", (bio or None, session["uid"]))
    db().commit()
    flash("Bio saved.")
    return redirect(request.referrer or "/")


@app.route("/avatar", methods=["POST"])
@login_required
def avatar():
    me = current_user()
    name = save_image(request.files.get("image"))
    if not name:
        flash("Please choose a JPG, PNG, GIF or WebP image.")
    else:
        db().execute("UPDATE users SET avatar=? WHERE id=?", (name, me["id"]))
        db().commit()
        if me["avatar"]:
            try:
                os.remove(os.path.join(UPLOADS, me["avatar"]))
            except OSError:
                pass
    return redirect(f"/u/{me['username']}")


@app.route("/people")
def people():
    me = current_user()
    rows = db().execute(
        """SELECT u.username, u.avatar, u.bio,
           EXISTS(SELECT 1 FROM follows f WHERE f.follower=? AND f.followed=u.id) AS following
           FROM users u WHERE u.id != ? ORDER BY u.id DESC LIMIT 100""",
        (me["id"], me["id"]),
    ).fetchall()
    return page(PEOPLE, rows=rows)


@app.route("/search")
def search():
    return page(SEARCH, q=request.args.get("q", "").strip()[:30])


@app.route("/search.json")
def search_json():
    q = request.args.get("q", "").strip().lower()[:30]
    rows = []
    if q:
        esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        rows = db().execute(
            "SELECT username, avatar FROM users WHERE username LIKE ? ESCAPE '\\' "
            "ORDER BY (username LIKE ? ESCAPE '\\') DESC, username LIMIT 20",
            (f"%{esc}%", f"{esc}%"),
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/follow/<name>", methods=["POST"])
@login_required
def follow(name):
    d, me = db(), session["uid"]
    t = d.execute("SELECT id FROM users WHERE username=?", (name,)).fetchone()
    if not t:
        abort(404)
    now_following = False
    if t["id"] != me:
        if follows(me, t["id"]):
            d.execute("DELETE FROM follows WHERE follower=? AND followed=?", (me, t["id"]))
        else:
            d.execute("INSERT INTO follows VALUES(?,?)", (me, t["id"]))
            now_following = True
        d.commit()
    if request.headers.get("X-Requested-With") == "fetch":
        n = d.execute("SELECT COUNT(*) FROM follows WHERE followed=?", (t["id"],)).fetchone()[0]
        return jsonify(following=now_following, followers=n)
    return redirect(f"/u/{name}")


# ---------- reels ----------
@app.route("/reels")
def reels():
    posts = fetch_posts("WHERE p.is_reel=1 AND p.repost_of IS NULL", uid=session["uid"])
    return page(REELS, posts=posts)


@app.route("/reel/new")
def reel_new():
    return page(REEL_NEW + EDITOR)


@app.route("/reel", methods=["POST"])
@login_required
def new_reel():
    f = request.files.get("media")
    vid = save_video(f, 30) if f and f.filename else None  # reels are short: 30 seconds max
    if not vid:
        flash("pick a video (mp4, mov or webm) for your reel.")
        return redirect("/reel/new")
    if not FFMPEG:
        flash("posted without trimming or cropping. in Termux run: pkg install ffmpeg")
    is_ad = 1 if request.form.get("is_ad") else 0
    ad_url = request.form.get("ad_url", "").strip()[:300] if is_ad else ""
    if ad_url and not ad_url.lower().startswith(("http://", "https://")):
        ad_url = ""
        flash("the ad link has to start with http:// or https://, so i left it out.")
    db().execute(
        "INSERT INTO posts(user_id,body,video,is_reel,allow_dl,is_ad,ad_url) VALUES(?,?,?,?,?,?,?)",
        (
            session["uid"], request.form.get("body", "").strip()[:200], vid, 1,
            1 if request.form.get("allow_dl") else 0, is_ad, ad_url or None,
        ),
    )
    db().commit()
    return redirect("/reels")


@app.route("/download/<int:pid>")
def download(pid):
    row = db().execute(
        """SELECT p.video, p.allow_dl, p.user_id, u.username FROM posts p
           JOIN users u ON u.id=p.user_id
           WHERE p.id=? AND p.repost_of IS NULL AND p.video IS NOT NULL""",
        (pid,),
    ).fetchone()
    if not row:
        abort(404)
    if not row["allow_dl"] and row["user_id"] != session["uid"]:
        abort(403)  # the uploader didn't allow downloads
    ext = row["video"].rsplit(".", 1)[-1]
    return send_from_directory(
        UPLOADS, row["video"], as_attachment=True, download_name=f"{row['username']}-{pid}.{ext}"
    )


# ---------- stories ----------
@app.route("/story/new")
def story_new():
    return page(STORY_NEW + EDITOR)


@app.route("/story", methods=["POST"])
@login_required
def new_story():
    body = request.form.get("body", "").strip()[:280]
    bg = request.form.get("bg", 0, type=int) % 8
    f = request.files.get("media")
    kind = media = None
    if f and f.filename:
        media = save_image(f)
        if media:
            kind = "photo"
        else:
            media = save_video(f, 30)
            kind = "video" if media else None
        if not kind:
            flash("that file didn't work. use a JPG, PNG, GIF, WebP, MP4, MOV or WebM.")
            return redirect("/story/new")
    elif body:
        kind = "text"
    else:
        flash("add a photo, a video or some words first ✨")
        return redirect("/story/new")
    db().execute(
        "INSERT INTO stories(user_id,kind,media,body,bg) VALUES(?,?,?,?,?)",
        (session["uid"], kind, media, body, bg),
    )
    db().commit()
    return redirect("/")


@app.route("/s/<name>")
def story_view(name):
    me = current_user()
    rows = visible_stories(me["id"], name)
    if not rows:
        if name == me["username"]:
            return redirect("/story/new")
        flash("no stories rn 👀")
        return redirect(request.referrer or "/")
    mine = rows[0]["user_id"] == me["id"]
    stories = [dict(r) for r in rows]
    for s in stories:
        s["replies"] = []
    if mine:
        by_id = {s["id"]: s for s in stories}
        marks = ",".join("?" * len(by_id))
        for r in db().execute(
            f"""SELECT r.story_id, r.body, u.username FROM story_replies r
                JOIN users u ON u.id=r.user_id WHERE r.story_id IN ({marks}) ORDER BY r.id""",
            tuple(by_id),
        ):
            by_id[r["story_id"]]["replies"].append({"username": r["username"], "body": r["body"]})
    owner = {"username": rows[0]["username"], "avatar": rows[0]["avatar"]}
    return page(STORY_VIEW, stories=stories, owner=owner, mine=mine)


@app.route("/slike/<int:sid>", methods=["POST"])
@login_required
def story_like(sid):
    story_for(sid)
    return toggle_like("story_likes", "story_id", sid)


EMOJIS = ("🔥", "😭", "💀", "😍", "🥺")


@app.route("/sreply/<int:sid>", methods=["POST"])
@login_required
def story_reply(sid):
    s = story_for(sid)
    if s["user_id"] == session["uid"]:
        return jsonify(error="that's your own story"), 400
    emoji = request.form.get("emoji", "")
    body = emoji if emoji in EMOJIS else request.form.get("body", "").strip()[:200]
    if not body:
        return jsonify(error="say something first"), 400
    db().execute(
        "INSERT INTO story_replies(story_id,user_id,body) VALUES(?,?,?)", (sid, session["uid"], body)
    )
    db().commit()
    return jsonify(ok=True)


@app.route("/sview/<int:sid>", methods=["POST"])
@login_required
def story_seen(sid):
    s = story_for(sid)
    if s["user_id"] != session["uid"]:
        db().execute("INSERT OR IGNORE INTO story_views(user_id,story_id) VALUES(?,?)", (session["uid"], sid))
        db().commit()
    return "", 204


@app.route("/sdel/<int:sid>", methods=["POST"])
@login_required
def story_delete(sid):
    d = db()
    if d.execute("SELECT 1 FROM stories WHERE id=? AND user_id=?", (sid, session["uid"])).fetchone():
        for table, col in [("story_likes", "story_id"), ("story_views", "story_id"),
                           ("story_replies", "story_id"), ("stories", "id")]:
            d.execute(f"DELETE FROM {table} WHERE {col}=?", (sid,))
        d.commit()
    return jsonify(ok=True)


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
