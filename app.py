import mysql.connector
from flask import Flask, redirect, url_for, render_template, request, session, flash
from datetime import datetime

def connect_to_database():
    return mysql.connector.connect(
        host="cfif31.ru",
        user="ISPr24-38_KazancevKR",
        password="ISPr24-38_KazancevKR",
        database="ISPr24-38_KazancevKR_crm"
    )

def get_status_id_by_name(status_name):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        cursor.execute("SELECT id_status FROM status WHERE status_name = %s", (status_name,))
        result = cursor.fetchone()
        return result[0] if result else None

def get_role_id_by_name(role_name):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        cursor.execute("SELECT id_role FROM role WHERE role_name = %s", (role_name,))
        result = cursor.fetchone()
        return result[0] if result else None

def get_role_name_by_user(username):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        cursor.execute("""
            SELECT role.role_name 
            FROM users 
            JOIN role ON users.role_id = role.id_role 
            WHERE username = %s
        """, (username,))
        result = cursor.fetchone()
        return result[0] if result else None

def add_order(place, orders_disc, id_user):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        status_id = get_status_id_by_name("В обработке")
        sql = "INSERT INTO orders (place, orders_disc, data, id_user, status_id) VALUES (%s, %s, %s, %s, %s)"
        val = (place, orders_disc, datetime.now(), id_user, status_id)
        cursor.execute(sql, val)
        mydb.commit()

def get_id_user(username):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        sql = "SELECT id_users FROM users WHERE username = %s"
        val = (username,)
        cursor.execute(sql, val)
        result = cursor.fetchone()
        return result[0] if result else None

def register_user_to_db(username, password, role):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        role_id = get_role_id_by_name(role)
        sql = "INSERT INTO users (username, password, registration_date, role_id) VALUES (%s, %s, %s, %s)"
        val = (username, password, datetime.now(), role_id)
        cursor.execute(sql, val)
        mydb.commit()

def check_user(username, password):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        sql = "SELECT password FROM users WHERE username = %s"
        val = (username,)
        cursor.execute(sql, val)
        result = cursor.fetchone()
        return result[0] == password if result else False

def get_requests_by_status(id_user=None, status=None):
    with connect_to_database() as mydb:
        cursor = mydb.cursor(dictionary=True)
        
        if id_user and status:
            status_id = get_status_id_by_name(status)  
            sql = """SELECT o.*, s.status_name FROM orders o
                     JOIN status s ON o.status_id = s.id_status
                     WHERE o.id_user = %s AND o.status_id = %s"""
            val = (id_user, status_id)
        
        elif id_user:
            sql = """SELECT o.*, s.status_name FROM orders o
                     JOIN status s ON o.status_id = s.id_status
                     WHERE o.id_user = %s"""
            val = (id_user,)
        
        elif status:
            status_id = get_status_id_by_name(status)
            sql = """SELECT o.*, s.status_name FROM orders o
                     JOIN status s ON o.status_id = s.id_status
                     WHERE o.status_id = %s"""
            val = (status_id,)
        
        else:
            sql = """SELECT o.*, s.status_name FROM orders o
                     JOIN status s ON o.status_id = s.id_status"""
            val = ()
        
        cursor.execute(sql, val)
        return cursor.fetchall()

def get_active_requests():
    with connect_to_database() as mydb:
        cursor = mydb.cursor(dictionary=True)
        sql = "SELECT * FROM orders WHERE status_id NOT IN (1, 4)"  # 1 - Принята, 4 - Отклонена
        cursor.execute(sql)
        return cursor.fetchall()

def get_user_registration_date(id_user):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        sql = "SELECT registration_date FROM users WHERE id_users = %s"
        cursor.execute(sql, (id_user,))
        result = cursor.fetchone()
        return result[0] if result else None

def get_completed_requests_count(id_user):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        status_id = get_status_id_by_name("Завершена")
        sql = "SELECT COUNT(*) FROM orders WHERE id_user = %s AND status_id = %s"
        cursor.execute(sql, (id_user, status_id))
        result = cursor.fetchone()
        return result[0] if result else 0
    
def get_all_requests_count(id_user):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        
        sql = "SELECT COUNT(*) FROM orders WHERE id_user = %s"
        cursor.execute(sql, (id_user,))
        result = cursor.fetchone()

        return result[0] if result else 0


def get_completed_requests_counts(id_user):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        status_id = get_status_id_by_name("Завершена")
        sql = "SELECT COUNT(*) FROM orders WHERE accepted_by = %s AND status_id = %s"
        cursor.execute(sql, (id_user, status_id))
        result = cursor.fetchone()
        return result[0] if result else 0

def accept_order(order_id, accepted_by):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        status_id = get_status_id_by_name("Принята")
        sql = "UPDATE orders SET status_id = %s, accepted_by = %s WHERE id_orders = %s"
        cursor.execute(sql, (status_id, accepted_by, order_id))
        mydb.commit()

def get_user_role(username):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        cursor.execute("""
            SELECT r.role_name
            FROM users u
            JOIN role r ON u.role_id = r.id_role
            WHERE u.username = %s
        """, (username,))
        result = cursor.fetchone()
        return result[0] if result else None

def confirm_order_completion(id_orders, id_user):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        status_id = get_status_id_by_name("Завершена")
        sql = "UPDATE orders SET status_id = %s WHERE id_orders = %s AND id_user = %s"
        cursor.execute(sql, (status_id, id_orders, id_user))
        mydb.commit()

def update_order_status(order_id, new_status):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        status_id = get_status_id_by_name(new_status)
        sql = "UPDATE orders SET status_id = %s WHERE id_orders = %s"
        cursor.execute(sql, (status_id, order_id))
        mydb.commit()

def reject_order(order_id):
    with connect_to_database() as mydb:
        cursor = mydb.cursor()
        status_id = get_status_id_by_name("Отклонена")
        sql = "UPDATE orders SET status_id = %s WHERE id_orders = %s"
        cursor.execute(sql, (status_id, order_id))
        mydb.commit()

def get_faq():
    with connect_to_database() as db:
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM faq")
        return cursor.fetchall()

def get_messages_for_user(user_id):
    with connect_to_database() as db:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM messages
            WHERE sender_id = %s OR receiver_id = %s
            ORDER BY timestamp
        """, (user_id, user_id))
        return cursor.fetchall()
    
def get_conversation(user_id):
    with connect_to_database() as db:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT m.*, u.username
            FROM messages m
            JOIN users u ON m.sender_id = u.id_users
            WHERE m.sender_id = %s OR m.receiver_id = %s
            ORDER BY m.timestamp
        """, (user_id, user_id))
        return cursor.fetchall()
    
def get_user_status_changes(user_id):
    with connect_to_database() as db:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT o.id_orders, o.status_id, a.username as admin_name
            FROM orders o
            LEFT JOIN users a ON o.accepted_by = a.id_users
            WHERE o.id_user = %s
        """, (user_id,))
        return cursor.fetchall()

def get_users_with_messages():
    with connect_to_database() as db:
        cursor = db.cursor(dictionary=True)
        cursor.execute("""
            SELECT DISTINCT u.id_users, u.username
            FROM messages m
            JOIN users u ON m.sender_id = u.id_users OR m.receiver_id = u.id_users
            WHERE u.role_id = 2
        """)
        return cursor.fetchall()


app = Flask(__name__)
app.secret_key = "IT-service"

@app.route("/")
def index():
    return render_template('login.html')

@app.route("/toggle_theme")
def toggle_theme():
    session['theme'] = 'dark' if session.get('theme') != 'dark' else 'light'
    return redirect(request.referrer or url_for('index'))

ADMIN_SECRET_KEY = "school-118"
@app.route('/register', methods=["POST", "GET"])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form.get('role', 'user')

        if len(username) < 3 or len(password) < 3:
            flash("Логин и пароль должны содержать не менее 3 символов.", "danger")
            return redirect(url_for('register'))
        
        if len(username) > 10 or len(password) > 10:
            flash("Логин и пароль должны содержать не более 10 символов.", "danger")
            return redirect(url_for('register'))

        if role == 'admin':
            provided_key = request.form.get('admin_key')
            if provided_key != ADMIN_SECRET_KEY:
                flash("Неверный ключ администратора!", "danger")
                return redirect(url_for('register'))

        register_user_to_db(username, password, role)
        flash("Регистрация прошла успешно!", "success")
        return redirect(url_for('index'))
    else:
        return render_template('register.html')

@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if check_user(username, password):
            session['username'] = username
            session['role'] = get_user_role(username)
            flash("Вы успешно вошли в систему!", "success")
            return redirect(url_for('home'))
        else:
            flash("Неправильное имя пользователя или пароль", "danger")
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@app.before_request
def check_request_status_changes():
    if 'username' in session and request.endpoint != 'login' and not request.endpoint.startswith('static'):
        role = session.get('role')
        user_id = get_id_user(session['username'])

        if role == 'user':
            current_statuses = get_user_status_changes(user_id)
            previous_statuses = session.get('status_cache', {})
            for order in current_statuses:
                prev = previous_statuses.get(order['id_orders'])
                now = order['status_id']
                if prev and prev != now:
                    admin = order['admin_name'] or "Администратор"
                    if now == get_status_id_by_name("Принята"):
                        flash(f"Ваша заявка №{order['id_orders']} была принята ({admin})", "success")
                    elif now == get_status_id_by_name("Отклонена"):
                        flash(f"Ваша заявка №{order['id_orders']} была отклонена ({admin})", "danger")
            session['status_cache'] = {o['id_orders']: o['status_id'] for o in current_statuses}

        elif role == 'admin':
            with connect_to_database() as db:
                cursor = db.cursor(dictionary=True)
                cursor.execute("""
                    SELECT o.id_orders, u.username
                    FROM orders o
                    JOIN users u ON o.id_user = u.id_users
                    WHERE o.status_id = %s AND o.accepted_by = %s
                """, (get_status_id_by_name("Завершена"), user_id))
                confirmed = cursor.fetchall()
                for order in confirmed:
                    flash(f"Пользователь {order['username']} подтвердил выполнение заявки №{order['id_orders']}", "info")


@app.route('/profile')
def profile():
    if 'username' in session:
        role = get_user_role(session['username'])
        id_user = get_id_user(session['username'])
        registration_date = get_user_registration_date(id_user)
        faq = get_faq()
        messages = get_conversation(id_user)
        all_requests_count = get_all_requests_count(id_user)
        completed_requests_counts = get_completed_requests_counts(id_user)

        if role == 'admin':
            requests = get_requests_by_status(status="В обработке")
            history_requests = get_requests_by_status(status="Завершена")
            accepted_requests = get_requests_by_status(status="Принята")
            rejected_requests = get_requests_by_status(status="Отклонена")
            return render_template('admin.html', 
                                   username=session['username'], 
                                   id_user=id_user, 
                                   requests=requests, 
                                   history_requests=history_requests, 
                                   registration_date=registration_date, 
                                   completed_requests_counts=completed_requests_counts,
                                   accepted_requests=accepted_requests,
                                   rejected_requests=rejected_requests,
                                   theme=session.get('theme', 'light'))
        else:
            all_requests = get_requests_by_status(id_user)

            requests = [req for req in all_requests if req['status_id'] in [
                get_status_id_by_name("В обработке"), 
                get_status_id_by_name("Принята")
            ]]

            history_requests = [req for req in all_requests if req['status_id'] in [
                get_status_id_by_name("Завершена"), 
                get_status_id_by_name("Отклонена")
            ]]

            return render_template('user.html', 
                                   username=session['username'], 
                                   id_user=id_user, 
                                   requests=requests, 
                                   faq=faq,
                                   messages=messages,
                                   history_requests=history_requests, 
                                   registration_date=registration_date, 
                                   all_requests_count=all_requests_count,
                                   theme=session.get('theme', 'light'))
    else:
        flash("Пользователь не авторизован", "warning")
        return redirect(url_for('index'))

@app.route('/update_status', methods=['POST'])
def update_status():
    if 'username' in session and session.get('role') == 'admin':
        order_id = request.form.get('order_id')
        new_status = request.form.get('new_status')
        update_order_status(order_id, new_status)
        flash('Статус заявки обновлен', 'success')
        return redirect(url_for('admin'))
    else:
        flash('Недостаточно прав для выполнения этой операции', 'danger')
        return redirect(url_for('login'))
   
@app.route('/home', methods=['GET', 'POST'])
def home():
    if 'username' in session:
        if request.method == 'POST':
            id_user = get_id_user(session['username'])
            place = request.form['place']
            orders_disc = request.form['orders_disc']

            try:
                place_num = int(place)
                if not (1 <= place_num <= 20):
                    flash("Номер рабочего места должен быть числом от 1 до 20", "danger")
                    return redirect(url_for('home'))
            except ValueError:
                flash("Номер рабочего места должен быть числом", "danger")
                return redirect(url_for('home'))

            if not (2 <= len(orders_disc) <= 350):
                flash("Описание проблемы должно содержать от 2 до 350 символов", "danger")
                return redirect(url_for('home'))

            add_order(place, orders_disc, id_user)
            flash("Заявка добавлена!", "success")
            return redirect(url_for('home'))
        else:
            return render_template('home.html', username=session['username'], theme=session.get('theme', 'light'))
    else:
        flash("Пользователь не авторизован", "warning")
        return redirect(url_for('index'))

@app.route('/confirm_completion/<int:id_orders>', methods=['POST'])
def confirm_completion(id_orders):
    if 'username' in session and session.get('role') == 'user':
        user_id = get_id_user(session['username']) 
        confirm_order_completion(id_orders, user_id)
        flash("Заявка подтверждена!", "success")
        return redirect(url_for('profile'))
    else:
        flash("Пользователь не авторизован", "warning")
        return redirect(url_for('index'))

@app.route('/accept_request/<int:id_orders>', methods=['POST'])
def accept_request(id_orders):
    if 'username' in session and session.get('role') == 'admin':
        id_user = get_id_user(session['username'])
        accept_order(id_orders, id_user)
        flash("Заявка принята!", "success")
        return redirect(url_for('admin'))
    else:
        flash("Недостаточно прав для выполнения этой операции", "danger")
        return redirect(url_for('login'))

@app.route('/reject_request/<int:id_orders>', methods=['POST'])
def reject_request(id_orders):
    if 'username' in session and session.get('role') == 'admin':
        reject_order(id_orders)
        flash("Заявка отклонена!", "success")
        return redirect(url_for('admin'))
    else:
        flash("Недостаточно прав для выполнения этой операции", "danger")
        return redirect(url_for('login'))

@app.route('/admin')
def admin():
    if 'username' in session and session.get('role') == 'admin':
        id_user = get_id_user(session['username'])
        completed_requests_counts = get_completed_requests_counts(id_user)

        active_requests = get_requests_by_status(status="В обработке")

        accepted_requests = get_requests_by_status(status="Принята")
        rejected_requests = get_requests_by_status(status="Отклонена")
        history_requests = get_requests_by_status(status="Завершена")

        return render_template('admin.html', 
                               username=session['username'], 
                               requests=active_requests,
                               accepted_requests=accepted_requests,
                               rejected_requests=rejected_requests,
                               history_requests=history_requests,
                               completed_requests_counts=completed_requests_counts,
                               theme=session.get('theme', 'light'))
    else:
        flash('Недостаточно прав для доступа к этой странице', 'danger')
        return redirect(url_for('login'))
    
@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return redirect(url_for('index'))
    sender_id = get_id_user(session['username'])
    receiver_id = int(request.form['receiver_id'])
    content = request.form['content']
    with connect_to_database() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, content)
            VALUES (%s, %s, %s)
        """, (sender_id, receiver_id, content))
        db.commit()
    flash("Сообщение отправлено", "success")
    return redirect(url_for('profile'))

@app.route('/messages')
def messages():
    if 'username' not in session or session.get('role') != 'admin':
        flash('Доступ запрещён', 'danger')
        return redirect(url_for('login'))

    with connect_to_database() as db:
        cursor = db.cursor(dictionary=True)
        
        cursor.execute("""
            SELECT id_users, username FROM users
            WHERE role_id = (SELECT id_role FROM role WHERE role_name = 'user')
            ORDER BY username
        """)
        users = cursor.fetchall()

        selected_user = request.args.get('selected_user', None)
        if selected_user:
            try:
                selected_user = int(selected_user)
            except ValueError:
                selected_user = None
        else:
            selected_user = users[0]['id_users'] if users else None

        selected_username = None
        selected_user_messages = []

        if selected_user:
            cursor.execute("SELECT username FROM users WHERE id_users = %s", (selected_user,))
            res = cursor.fetchone()
            selected_username = res['username'] if res else None

            cursor.execute("""
                SELECT m.*, u.username as sender_username, r.role_name as sender_role
                FROM messages m
                JOIN users u ON m.sender_id = u.id_users
                JOIN role r ON u.role_id = r.id_role
                WHERE (m.sender_id = %s OR m.receiver_id = %s)
                  AND (m.sender_id IN (SELECT id_users FROM users WHERE role_id = (SELECT id_role FROM role WHERE role_name = 'admin'))
                  OR m.receiver_id IN (SELECT id_users FROM users WHERE role_id = (SELECT id_role FROM role WHERE role_name = 'admin')))
                ORDER BY m.timestamp
            """, (selected_user, selected_user))
            selected_user_messages = cursor.fetchall()

    return render_template(
        'messages.html',
        users=users,
        selected_user=selected_user,
        selected_username=selected_username,
        selected_user_messages=selected_user_messages
    )

@app.route('/admin_reply/<int:user_id>', methods=['POST'])
def admin_reply(user_id):
    if 'username' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    sender_id = get_id_user(session['username'])
    content = request.form['content']
    with connect_to_database() as db:
        cursor = db.cursor()
        cursor.execute("""
            INSERT INTO messages (sender_id, receiver_id, content)
            VALUES (%s, %s, %s)
        """, (sender_id, user_id, content))
        db.commit()
    return redirect(url_for('messages'))

@app.route('/logout')
def logout():
    session.clear()
    session.pop('username', None)
    flash("Вы вышли из системы", "info")
    return redirect(url_for('index'))
    

if __name__ == "__main__":
    app.run(debug=True)
