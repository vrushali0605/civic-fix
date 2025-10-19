import sqlite3, random, datetime, os
from flask import Flask, request, redirect, url_for, render_template, session , jsonify, flash
from werkzeug.utils import secure_filename
from twilio.rest import Client
from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import timedelta


# --- Hardcoded Admin ---
ADMIN_USERNAME = "admin@gmail.com"
ADMIN_PASSWORD_HASH = generate_password_hash("admin123")

# --- Load Env ---
load_dotenv()

app = Flask(__name__)
app.secret_key = "supersecretkey"

# --- Twilio ---
TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE = os.getenv("TWILIO_PHONE")
client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)

DATABASE = 'civicfix.db'
UPLOAD_FOLDER = os.path.join("static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# --- DB ---
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# --- Init DB ---
def init_db():
    with open('schema.sql') as f:
        conn = get_db()
        conn.executescript(f.read())
        conn.commit()
        conn.close()

# --- Home ---
@app.route('/')
def frontpage():
    return render_template('frontPage.html')

# --- Register ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        action = request.form['action']
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')

        conn = get_db()
        cursor = conn.cursor()

        if action == 'send_otp':
            cursor.execute('SELECT * FROM users WHERE email=? OR phone=?', (email, phone))
            if cursor.fetchone():
                conn.close()
                return "User already exists with this email or phone."

            otp = str(random.randint(100000, 999999))
            expires_at = datetime.datetime.now() + datetime.timedelta(minutes=5)

            cursor.execute('INSERT INTO users (name, email, phone, otp, otp_expires_at) VALUES (?, ?, ?, ?, ?)',
                           (name, email, phone, otp, expires_at))
            conn.commit()

            try:
                client.messages.create(
                    body=f"Your CivicFix OTP is {otp}. It will expire in 5 minutes.",
                    from_=TWILIO_PHONE,
                    to=phone
                )
            except Exception as e:
                print("Error sending OTP:", e)
                return "Failed to send OTP. Please check number or Twilio setup."

            conn.close()
            return render_template('register.html', otp_sent=True, name=name, email=email, phone=phone)

        elif action == 'verify_otp':
            otp = request.form.get('otp')

            cursor.execute(
                'SELECT * FROM users WHERE email=? AND phone=? AND otp=? AND otp_expires_at > ?',
                (email, phone, otp, datetime.datetime.now())
            )
            user = cursor.fetchone()

            if user:
                cursor.execute('UPDATE users SET otp=NULL, otp_expires_at=NULL WHERE id=?', (user['id'],))
                conn.commit()
                conn.close()
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                return redirect(url_for('user_home'))
            else:
                conn.close()
                return render_template('register.html', otp_sent=True, name=name, email=email, phone=phone, error="Invalid or expired OTP.")

    return render_template('register.html')

# --- Login ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, skip login
    if session.get('user_id'):
        return redirect(url_for('user_home'))

    if request.method == 'POST':
        action = request.form.get('action')
        phone = request.form.get('phone')

        if not phone:
            return "Phone number is required."

        conn = get_db()
        cursor = conn.cursor()

        if action == 'send_otp':
            # Check if phone is already registered
            cursor.execute('SELECT * FROM users WHERE phone=?', (phone,))
            user = cursor.fetchone()

            if not user:
                conn.close()
                return "Phone number not registered."

            otp = str(random.randint(100000, 999999))
            expires_at = datetime.datetime.now() + datetime.timedelta(minutes=5)

            # Save OTP and expiration
            cursor.execute('UPDATE users SET otp=?, otp_expires_at=? WHERE phone=?',
                           (otp, expires_at, phone))
            conn.commit()

            client.messages.create(
                body=f"Your CivicFix OTP is {otp}. Expires in 5 minutes.",
                from_=TWILIO_PHONE,
                to=phone
            )

            conn.close()
            return render_template('userLogin.html', otp_sent=True, phone=phone)

        elif action == 'verify_otp':
            otp = request.form.get('otp')

            if not otp:
                conn.close()
                return "OTP is required."

            cursor.execute(
                'SELECT * FROM users WHERE phone=? AND otp=? AND otp_expires_at > ?',
                (phone, otp, datetime.datetime.now())
            )
            user = cursor.fetchone()
            conn.close()

            if user:
                # Set session and make it permanent
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session.permanent = True  # Session will persist
                return redirect(url_for('user_home'))
            else:
                return render_template('userLogin.html', error="Invalid or expired OTP.", otp_sent=True, phone=phone)

    return render_template('userLogin.html')

# --- User Home ---
@app.route('/user-home')
def user_home():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('user_home.html')

#-----about us----#
@app.route('/aboutUs')
def about_us():
    return render_template('aboutUs.html')

# --- Upload page ---
@app.route('/upload')
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('upload.html')

# --- Complaint form ---
import requests  # for geocoding

def geocode_location(address):
    url = "https://nominatim.openstreetmap.org/search"
    params = {'q': address, 'format': 'json', 'limit': 1}
    headers = {'User-Agent': 'CivicFix-App'}
    response = requests.get(url, params=params, headers=headers)
    data = response.json()
    if data:
        return float(data[0]['lat']), float(data[0]['lon'])
    return None, None


@app.route('/complaint-form', methods=['GET', 'POST'])
def complaint_form():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        subject = request.form['subject']
        description = request.form['description']
        location = request.form.get('location') or "Unknown"
        category = request.form['category']

        # Get GPS from hidden fields
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')

        # Handle photo
        photo_file = request.files['photo']
        photo_filename = None
        if photo_file and photo_file.filename != '':
            photo_filename = secure_filename(photo_file.filename)
            photo_path = os.path.join(UPLOAD_FOLDER, photo_filename)
            photo_file.save(photo_path)

        # Fallback: geocode location if GPS not provided
        if not latitude or not longitude or latitude == '' or longitude == '':
            lat, lng = geocode_location(location)
        else:
            lat, lng = float(latitude), float(longitude)

        # Insert complaint
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO complaints (user_id, subject, description, location, photo, category, latitude, longitude)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], subject, description, location, photo_filename, category, lat, lng))

        complaint_id = cursor.lastrowid
        cursor.execute('''
            INSERT INTO escalations (complaint_id, current_level, reason)
            VALUES (?, 1, ?)
        ''', (complaint_id, "Initial submission"))

        conn.commit()
        conn.close()

        return redirect(url_for('complaint_success'))

    category = request.args.get('category', 'Others')
    return render_template('complaint-form.html', category=category)

#-----complaint success----#
@app.route('/complaint-success')
def complaint_success():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('complaint_success.html')
 
 #-----complaint status----#
@app.route('/complaint-status')
def complaint_status():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT c.id, c.category, c.subject, c.description, c.status, c.created_at,
               IFNULL(e.current_level, 1) AS escalation_level
        FROM complaints c
        LEFT JOIN escalations e ON c.id = e.complaint_id
        WHERE c.user_id = ?
    """, (session['user_id'],))
    complaints = cursor.fetchall()
    conn.close()
    return render_template('complaint_status.html', complaints=complaints)


#------complaint escalation----#
@app.route('/escalate', methods=['POST'])
def escalate():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    complaint_id = request.form.get('complaint_id')
    reason = request.form.get('reason')
    if not complaint_id or not reason:
        return "Complaint ID and Reason are required.", 400
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT current_level FROM escalations WHERE complaint_id = ?", (complaint_id,))
    existing = cursor.fetchone()
    if existing:
        if existing['current_level'] >= 3:
            conn.close()
            return "This complaint is already at the maximum escalation level."
        new_level = existing['current_level'] + 1
        cursor.execute("UPDATE escalations SET current_level = ?, reason = ?, updated_at = CURRENT_TIMESTAMP WHERE complaint_id = ?", (new_level, reason, complaint_id))
    else:
        cursor.execute("INSERT INTO escalations (complaint_id, current_level, reason) VALUES (?, 1, ?)", (complaint_id, reason))
    conn.commit()
    conn.close()
    return redirect(url_for('complaint_status'))



# --- Admin Login ---
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    if request.method == 'POST':
        username = request.form['adminId']
        password = request.form['password']
        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        return render_template('adminLogin.html', error="Invalid credentials")
    return render_template('adminLogin.html')

#------admin dashboard----#
@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM complaints")
    total_complaints = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM users")
    total_users = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM complaints WHERE status = 'Resolved'")
    resolved_complaints = cursor.fetchone()[0]
    conn.close()
    return render_template('adminDashboard.html', total_complaints=total_complaints, total_users=total_users, resolved_complaints=resolved_complaints)

#------admin manage users----#
@app.route('/admin/users')
def admin_users():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""SELECT u.id, u.name, u.email, u.phone, (SELECT COUNT(*) FROM complaints WHERE user_id = u.id) AS complaint_count FROM users u""")
    users = cursor.fetchall()
    conn.close()
    return render_template('adminUsers.html', users=users)

#-------admin manage complaints----#
@app.route('/admin/complaints')
def admin_complaints():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""SELECT c.id AS complaint_id, c.user_id, u.name AS user_name, c.subject, c.description, c.location, c.photo, c.category, c.status, c.created_at FROM complaints c LEFT JOIN users u ON c.user_id = u.id ORDER BY c.created_at DESC""")
    complaints = cursor.fetchall()
    conn.close()
    return render_template('adminComplaints.html', complaints=complaints)

#--------admin manage status----#
@app.route('/admin/status', methods=['GET', 'POST'])
def admin_status():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cursor = conn.cursor()

    if request.method == 'POST':
        complaint_id = request.form['complaint_id']
        new_status = request.form['status']

        # Get the user_id for this complaint
        cursor.execute("SELECT user_id FROM complaints WHERE id = ?", (complaint_id,))
        user = cursor.fetchone()
        if not user:
            conn.close()
            return redirect(url_for('admin_status'))
        user_id = user['user_id']

        # Update complaints table
        cursor.execute("UPDATE complaints SET status = ? WHERE id = ?", (new_status, complaint_id))

        # Insert into status_log with proper timestamp
        cursor.execute("""
            INSERT INTO status_log (complaint_id, user_id, status, timestamp)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        """, (complaint_id, user_id, new_status))

        conn.commit()

    # Fetch complaints for admin table
    cursor.execute("""
        SELECT c.id, c.subject, c.status, u.name AS user_name 
        FROM complaints c 
        JOIN users u ON c.user_id = u.id
    """)
    complaints = cursor.fetchall()
    conn.close()
    return render_template('adminStatus.html', complaints=complaints)

#-------admin manage escalation-----#
@app.route('/admin/escalations', methods=['GET', 'POST'])
def admin_escalations():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cursor = conn.cursor()
    if request.method == 'POST':
        escalation_id = request.form.get('escalation_id')
        if escalation_id:
            cursor.execute("SELECT current_level FROM escalations WHERE id = ?", (escalation_id,))
            escalation = cursor.fetchone()
            if escalation and escalation['current_level'] < 3:
                new_level = escalation['current_level'] + 1
                cursor.execute("UPDATE escalations SET current_level = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (new_level, escalation_id))
                conn.commit()
    cursor.execute("""SELECT e.id, e.complaint_id, e.current_level, e.reason, e.created_at, e.updated_at, c.subject, u.name AS user_name FROM escalations e LEFT JOIN complaints c ON e.complaint_id = c.id LEFT JOIN users u ON c.user_id = u.id ORDER BY e.created_at DESC""")
    escalations = cursor.fetchall()
    conn.close()
    return render_template('adminEscalations.html', escalations=escalations)

# ---- ADMIN  manage POLLS ----
@app.route("/admin/polls", methods=["GET", "POST"])
def admin_polls():
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    cur = conn.cursor()
    if request.method == "POST":
        description = request.form['description']
        expires_at = request.form['expires_at']
        options = request.form.getlist('options[]')
        cur.execute("INSERT INTO polls (description, expires_at) VALUES (?, ?)", (description, expires_at))
        poll_id = cur.lastrowid
        for opt in options:
            cur.execute("INSERT INTO poll_options (poll_id, option_text) VALUES (?, ?)", (poll_id, opt))
        conn.commit()
    cur.execute("SELECT * FROM polls ORDER BY datetime(expires_at) DESC")
    polls = cur.fetchall()
    conn.close()
    return render_template("adminPolls.html", polls=polls)

@app.route('/admin/poll_results/<int:poll_id>')
def admin_poll_results(poll_id):
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login'))
    conn = get_db()
    poll = conn.execute('SELECT * FROM polls WHERE id = ?', (poll_id,)).fetchone()
    options = conn.execute('''SELECT o.id, o.option_text, (SELECT COUNT(*) FROM poll_votes v WHERE v.option_id = o.id) AS votes FROM poll_options o WHERE o.poll_id = ?''', (poll_id,)).fetchall()
    total_votes = conn.execute('SELECT COUNT(*) FROM poll_votes WHERE poll_id = ?', (poll_id,)).fetchone()[0]
    conn.close()
    return render_template('adminPollResults.html', poll=poll, options=options, total_votes=total_votes)


# ---- USER POLLS ----
@app.route("/polls")
def polls():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session.get("user_id")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM polls WHERE datetime(expires_at) > datetime('now')")
    active_polls = cur.fetchall()
    polls_data = []
    for poll in active_polls:
        cur.execute("SELECT * FROM poll_options WHERE poll_id=?", (poll['id'],))
        options = cur.fetchall()
        cur.execute("SELECT option_id FROM poll_votes WHERE poll_id=? AND user_id=?", (poll['id'], user_id))
        user_vote = cur.fetchone()
        total_votes = 0
        for opt in options:
            cur.execute("SELECT COUNT(*) FROM poll_votes WHERE option_id=?", (opt['id'],))
            total_votes += cur.fetchone()[0]
        option_data = []
        for opt in options:
            cur.execute("SELECT COUNT(*) FROM poll_votes WHERE option_id=?", (opt['id'],))
            votes = cur.fetchone()[0]
            percentage = round((votes / total_votes) * 100, 2) if total_votes > 0 else 0
            option_data.append({"id": opt['id'], "option_text": opt['option_text'], "votes": votes, "percentage": percentage})
        polls_data.append({"id": poll['id'], "description": poll['description'], "options": option_data, "total_votes": total_votes, "user_vote": user_vote})
    conn.close()
    return render_template("polls.html", polls=polls_data)

@app.route("/vote-poll", methods=["POST"])
def vote_poll():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    poll_id = request.form['poll_id']
    option_id = request.form['option_id']
    user_id = session.get("user_id")
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM poll_votes WHERE poll_id=? AND user_id=?", (poll_id, user_id))
    if not cur.fetchone():
        cur.execute("INSERT INTO poll_votes (poll_id, option_id, user_id) VALUES (?, ?, ?)", (poll_id, option_id, user_id))
        conn.commit()
    conn.close()
    return redirect(url_for('polls'))

#------user views old polls----#
@app.route("/old-polls")
def old_polls():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT * FROM polls WHERE datetime(expires_at) <= datetime('now')")
    old_polls = cur.fetchall()
    polls_data = []
    for poll in old_polls:
        cur.execute("SELECT * FROM poll_options WHERE poll_id=?", (poll['id'],))
        options = cur.fetchall()
        total_votes = 0
        option_votes = []
        for opt in options:
            cur.execute("SELECT COUNT(*) FROM poll_votes WHERE option_id=?", (opt['id'],))
            count = cur.fetchone()[0]
            total_votes += count
            option_votes.append((opt['id'], count))

        # Find max votes for this poll
        max_votes = max([v for _, v in option_votes], default=0)

        # Build options with winner flag
        option_data = []
        for opt in options:
            cur.execute("SELECT COUNT(*) FROM poll_votes WHERE option_id=?", (opt['id'],))
            votes = cur.fetchone()[0]
            percentage = round((votes / total_votes) * 100, 2) if total_votes > 0 else 0
            option_data.append({
                "option_text": opt['option_text'],
                "votes": votes,
                "percentage": percentage,
                "is_winner": votes == max_votes and max_votes > 0
            })
        polls_data.append({
            "id": poll['id'],
            "description": poll['description'],
            "options": option_data,
            "total_votes": total_votes
        })
    conn.close()
    return render_template("old_polls.html", polls=polls_data)

#-----admin manages feedbacks-----#
@app.route('/admin/feedback')
def admin_feedback():
    conn = sqlite3.connect('civicfix.db')
    conn.row_factory = sqlite3.Row
    feedbacks = conn.execute('SELECT * FROM feedback ORDER BY created_at DESC').fetchall()
    conn.close()
    return render_template('adminFeedback.html', feedbacks=feedbacks)

# --- Admin Logout ---
@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

#----static pages-----#

@app.route('/policies')
def policies():
    return render_template('policies.html')

# @app.route('/heatmap')
# def heatmap():
#     return render_template('heatmap.html')

#------YOU page-------#

@app.route('/You')
def you():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()

    # Total complaints
    cursor.execute("SELECT COUNT(*) FROM complaints WHERE user_id = ?", (user_id,))
    total_complaints = cursor.fetchone()[0]

    # Resolved complaints
    cursor.execute("""
        SELECT COUNT(*) 
        FROM status_log sl
        JOIN complaints c ON sl.complaint_id = c.id
        WHERE c.user_id = ? AND sl.status = 'Resolved'
    """, (user_id,))
    resolved = cursor.fetchone()[0]

    # Pending complaints (total - resolved)
    pending = total_complaints - resolved

    # Escalations
    cursor.execute("""
        SELECT COUNT(*) 
        FROM escalations e
        JOIN complaints c ON e.complaint_id = c.id
        WHERE c.user_id = ?
    """, (user_id,))
    escalations = cursor.fetchone()[0]

    # Recent complaints with latest status
    cursor.execute("""
        SELECT 
            c.subject, c.created_at,
            (SELECT status FROM status_log 
             WHERE complaint_id = c.id 
             ORDER BY timestamp DESC LIMIT 1) as status
        FROM complaints c
        WHERE c.user_id = ?
        ORDER BY c.created_at DESC
        LIMIT 5
    """, (user_id,))
    recent_complaints = cursor.fetchall()

    conn.close()

    return render_template(
        'you.html',
        total_complaints=total_complaints,
        resolved=resolved,
        pending=pending,
        escalations=escalations,
        recent_complaints=recent_complaints,
    )

#------view profile-----#
@app.route('/view-profile')
def view_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect('civicfix.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT name, email, phone FROM users WHERE id = ?", (session['user_id'],))
    user = cursor.fetchone()
    conn.close()

    return render_template('viewProfile.html', user=user)

#------View complaints------#
@app.route('/view-complaints')
def view_complaints():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    complaints = conn.execute(
        'SELECT subject, description, created_at FROM complaints WHERE user_id = ? ORDER BY created_at DESC',
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('viewComplaints.html', complaints=complaints)

#--------user view complaint status----#
@app.route('/view-status')
def view_status():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()

    # Get each complaint with its latest status update
    cursor.execute("""
        SELECT 
            c.id AS complaint_id,
            c.subject,
            c.description,
            sl.status,
            sl.timestamp
        FROM complaints c
        LEFT JOIN (
            SELECT complaint_id, status, timestamp
            FROM status_log
            WHERE (complaint_id, timestamp) IN (
                SELECT complaint_id, MAX(timestamp) 
                FROM status_log 
                GROUP BY complaint_id
            )
        ) sl ON c.id = sl.complaint_id
        WHERE c.user_id = ?
        ORDER BY sl.timestamp DESC
    """, (user_id,))
    
    statuses = cursor.fetchall()
    conn.close()
    return render_template('viewStatus.html', statuses=statuses)

#------user view escalation -----#
@app.route('/view-escalations')
def view_escalations():
    if not session.get('user_id'):
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT e.complaint_id, e.current_level, e.reason, e.created_at, e.updated_at, c.subject
        FROM escalations e
        JOIN complaints c ON e.complaint_id = c.id
        WHERE c.user_id = ?
        ORDER BY e.updated_at DESC
    """, (user_id,))
    escalations = cursor.fetchall()
    conn.close()
    return render_template('viewEscalations.html', escalations=escalations)

#-------User logout------#
@app.route('/logout')
def logout():
    session.clear()  # Clears all session data
    return redirect(url_for('login'))  # Redirect to user login page

#-------user feedback----#
# Route to show feedback form
@app.route('/feedback')
def feedback():
    return render_template('feedback.html')  # your form page

# Route to handle feedback submission
@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    name = request.form['name']
    email = request.form['email']
    message = request.form['message']
    category= request.form['category']

    conn = get_db()
    conn.execute(
        'INSERT INTO feedback (name, email, message,category) VALUES (?, ?, ?, ?)',
        (name, email, message,category)
    )
    conn.commit()
    conn.close()

    # Redirect to success page
    return redirect(url_for('feedback_success'))

# Route to show feedback success page
@app.route('/feedback_success')
def feedback_success():
    return render_template('feedback_success.html')  # your success page

# ------ Heatmap Information Page ------ #
@app.route('/heatmap-info')
def heatmap_info():
    return render_template('heatmapInfo.html')  # Static info page


# ------ Heatmap on User Side ------ #
@app.route('/heatmap')
def heatmap_page():
    return render_template('heatmap.html')  # Actual interactive heatmap


# ------ API to Provide Complaint Data ------ #
@app.route('/api/complaints')
def get_complaints():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT latitude, longitude, status 
        FROM complaints 
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
    """)
    data = cursor.fetchall()
    conn.close()

    complaints = [{"lat": row[0], "lng": row[1], "status": row[2]} for row in data]
    return jsonify(complaints)


    if __name__ == "__main__":
        app.run(debug=True)


