from flask import Flask, render_template, request, redirect, url_for, flash
import pymssql
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash
import random
import string

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Подключение к БД (через pymssql)
def get_db_connection():
    return pymssql.connect(
        server='192.168.0.6.253',
        port=1433,
        user='sa',
        password='1234',
        database='BusinessCenter'
    )

def generate_temp_password(length=8):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# Главная
@app.route('/')
def home():
    return render_template('index.html')

# Подача заявки
@app.route('/application', methods=['GET', 'POST'])
def application_form():
    if request.method == 'POST':
        consent = request.form.get('consent')
        if not consent:
            flash('Необходимо согласие на обработку персональных данных.')
            return redirect(url_for('application_form'))

        username = request.form['Username']
        email = request.form['Email']
        title = request.form['title']
        description = request.form['description']

        conn = get_db_connection()
        cursor = conn.cursor()

        # Проверка — есть ли уже такой пользователь
        cursor.execute("""
            SELECT PublicUser_ID FROM PublicUsers WHERE Username = ? AND Email = ?
        """, (username, email))
        user = cursor.fetchone()

        if not user:
            cursor.execute("""
                INSERT INTO PublicUsers (Username, Email)
                VALUES (?, ?)
            """, (username, email))
            conn.commit()
            cursor.execute("""
                SELECT PublicUser_ID FROM PublicUsers WHERE Username = ? AND Email = ?
            """, (username, email))
            user = cursor.fetchone()

        public_user_id = user.PublicUser_ID
        cursor.execute("""
            INSERT INTO PublicApplications (PublicUser_ID, Title, Description)
            VALUES (?, ?, ?)
        """, (public_user_id, title, description))
        conn.commit()

        return redirect(url_for('application_success'))

    return render_template('application_form.html')

# Успех
@app.route('/application_success')
def application_success():
    return render_template('application_success.html')

# Просмотр заявок по имени
@app.route('/my_applications', methods=['GET', 'POST'])
def my_applications():
    if request.method == 'POST':
        username = request.form['Username']
        email = request.form['Email']

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT PublicUser_ID FROM PublicUsers WHERE Username = ? AND Email = ?
        """, (username, email))
        user = cursor.fetchone()

        if not user:
            flash('Пользователь не найден.')
            return redirect(url_for('my_applications'))

        public_user_id = user.PublicUser_ID
        cursor.execute("""
            SELECT Title, Description, Status, SubmissionDate
            FROM PublicApplications
            WHERE PublicUser_ID = ?
        """, (public_user_id,))
        applications = cursor.fetchall()

        return render_template('my_applications_result.html', applications=applications, username=username)

    return render_template('my_applications_form.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('Username')
        password = request.form.get('Password')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT User_ID, Password, Role_ID FROM Users WHERE Username = ?", (username,))
        user = cursor.fetchone()

        if user and check_password_hash(user.Password, password):
            role_id = user.Role_ID
            if role_id == 2:
                return redirect(url_for('admin_dashboard'))
            elif role_id == 1:
                return redirect(url_for('manager_dashboard'))
            else:
                flash('Ваша роль не имеет доступа.')
                return redirect(url_for('login'))
        else:
            flash('Неверный логин или пароль. Вы сотрудник? Напишите администратору.')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        username = request.form.get('Username')
        message = request.form.get('Message')

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO SupportMessages (Username, MessageText, CreatedAt)
            VALUES (?, ?, GETDATE())
        """, (username, message))
        conn.commit()

        flash("Ваше сообщение отправлено администратору. Ожидайте обратной связи по указанной вами почте.", "success")
        return redirect(url_for('login'))

    return render_template('support_form.html')



@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        username = request.form['Username']
        email = request.form['Email']
        new_password = request.form['NewPassword']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM Users WHERE Username = ? AND Email = ?
        """, (username, email))
        user = cursor.fetchone()

        if user:
            hashed_password = generate_password_hash(new_password)
            cursor.execute("""
                UPDATE Users SET Password = ? WHERE User_ID = ?
            """, (hashed_password, user.User_ID))
            conn.commit()
            flash('Пароль успешно сброшен. Используйте его при следующем входе.')
            return redirect(url_for('login'))
        else:
            flash('Пользователь не найден.')
            return redirect(url_for('reset_password'))

    return render_template('reset_password.html')

@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    request_sent = False

    if request.method == 'POST':
        username = request.form['Username']
        email = request.form['Email']

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO PasswordResetRequests (Username, Email)
            VALUES (?, ?)
        """, (username, email))
        conn.commit()
        request_sent = True

    return render_template('reset_password_request.html', request_sent=request_sent)

# Главное меню администратора
@app.route('/admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

# Управление пользователями
@app.route('/admin_users')
def admin_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT u.User_ID,
               u.Username,
               u.LastName + ' ' +
               LEFT(u.FirstName, 1) + '.' +
               LEFT(ISNULL(u.MiddleName, ''), 1) + '.' AS ShortName,
               u.Email,
               r.RoleName
        FROM Users u
        JOIN Roles r ON u.Role_ID = r.Role_ID
    """)
    users = cursor.fetchall()
    return render_template('admin_users.html', users=users)

# Сообщения поддержки
@app.route('/admin_support')
def admin_support():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT Message_ID, Username, MessageText, CreatedAt FROM SupportMessages ORDER BY CreatedAt DESC")
    messages = cursor.fetchall()
    return render_template('admin_support.html', messages=messages)

# Запросы на восстановление пароля
@app.route('/admin_reset_requests')
def admin_reset_requests():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT Username, Email, RequestedAt, Status
        FROM PasswordResetRequests
        ORDER BY RequestedAt DESC
    """)
    requests = cursor.fetchall()
    return render_template('admin_reset_requests.html', requests=requests)

# Журнал действий
@app.route('/admin_logs')
def admin_logs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT Username, Action, ActionTime
        FROM Logs
        ORDER BY ActionTime DESC
    """)
    logs = cursor.fetchall()
    return render_template('admin_logs.html', logs=logs)

@app.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        last_name = request.form.get('LastName')
        first_name = request.form.get('FirstName')
        middle_name = request.form.get('MiddleName', '')
        username = request.form.get('Username')
        email = request.form.get('Email')
        role_id = request.form.get('Role_ID')
        temp_password = generate_temp_password()
        hashed_password = generate_password_hash(temp_password)

        if not last_name or not first_name or not username or not email or not role_id:
            flash('Пожалуйста, заполните все обязательные поля.', 'danger')
            return redirect(url_for('add_user'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO Users (LastName, FirstName, MiddleName, Username, Password, Email, Role_ID)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (last_name, first_name, middle_name, username, hashed_password, email, role_id)
        )
        conn.commit()
        flash(f'Пользователь добавлен. Временный пароль: {temp_password}', 'success')
        return redirect(url_for('admin_users'))

    return render_template('add_user.html')

@app.route('/delete_user/<int:user_id>')
def delete_user(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM Users WHERE User_ID = ?", (user_id,))
    conn.commit()
    flash("Пользователь удалён.", "success")
    return redirect(url_for('admin_users'))

@app.route('/reset_user_password/<int:user_id>')
def reset_user_password(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Получаем имя пользователя по ID
    cursor.execute("SELECT Username, Email FROM Users WHERE User_ID = ?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("Пользователь не найден.", "danger")
        return redirect(url_for('admin_users'))

    temp_password = generate_temp_password()
    hashed_password = generate_password_hash(temp_password)

    # Обновляем пароль в таблице Users
    cursor.execute("UPDATE Users SET Password = ? WHERE User_ID = ?", (hashed_password, user_id))

    # Обновляем статус последнего запроса на восстановление, если был
    cursor.execute("""
        UPDATE PasswordResetRequests
        SET Status = 'Выполнено'
        WHERE Username = ? AND Email = ? AND Status = 'Ожидает'
    """, (user.Username, user.Email))

    # Логируем
    log_action('admin', f'Админ сбросил пароль для пользователя {user.Username}')
    conn.commit()

    flash(f"Пароль для {user.Username} сброшен. Новый временный пароль: {temp_password}", "success")
    return redirect(url_for('admin_users'))

@app.route('/delete_support_message/<int:message_id>')
def delete_support_message(message_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM SupportMessages WHERE Message_ID = ?", (message_id,))
    conn.commit()
    flash("Сообщение удалено.", "success")
    return redirect(url_for('admin_support'))

def log_action(username, action):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO Logs (Username, Action) VALUES (?, ?)
    """, (username, action))
    conn.commit()

@app.route('/manager_dashboard', methods=['GET', 'POST'])
def manager_dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Получаем фильтры из формы
    selected_status = request.form.get('status_filter', 'Все')
    user_filter = request.form.get('user_filter', '').strip().lower()
    executor_filter = request.form.get('executor_filter', 'all')

    # Загружаем заявки + имя пользователя
    cursor.execute("""
        SELECT pa.Application_ID, pa.Title, pa.Description, pa.Status, pa.SubmissionDate,
               pu.UserName
        FROM PublicApplications pa
        JOIN PublicUsers pu ON pa.PublicUser_ID = pu.PublicUser_ID
        ORDER BY pa.SubmissionDate DESC
    """)
    all_apps = cursor.fetchall()

    # Список заявок (отфильтрованный)
    applications = []

    assignments = {}

    for app in all_apps:
        app_id = app.Application_ID

        # Получаем назначенных исполнителей на каждую заявку
        cursor.execute("""
            SELECT u.User_ID, u.LastName, u.FirstName, u.MiddleName
            FROM ApplicationAssignments aa
            JOIN Users u ON aa.User_ID = u.User_ID
            WHERE aa.Application_ID = ?
        """, (app_id,))
        users = cursor.fetchall()
        assignments[app_id] = users

        # ======== ФИЛЬТРАЦИЯ ========
        # По статусу
        if selected_status != 'Все' and app.Status != selected_status:
            continue

        # По пользователю
        if user_filter and user_filter not in app.UserName.lower():
            continue

        # По исполнителю
        if executor_filter == 'with' and not users:
            continue
        if executor_filter == 'without' and users:
            continue

        applications.append(app)

    # Список всех сотрудников (не админов)
    cursor.execute("""
        SELECT User_ID, LastName, FirstName, MiddleName
        FROM Users
        WHERE Role_ID != 2
    """)
    available_users = cursor.fetchall()

    return render_template('manager_dashboard.html',
                           applications=applications,
                           assignments=assignments,
                           available_users=available_users,
                           selected_status=selected_status,
                           user_filter=user_filter,
                           executor_filter=executor_filter)

@app.route('/update_application_status/<int:app_id>', methods=['POST'])
def update_application_status(app_id):
    new_status = request.form['Status']

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE PublicApplications SET Status = ? WHERE Application_ID = ?
    """, (new_status, app_id))

    log_action('manager', f'Менеджер изменил статус заявки ID {app_id} на "{new_status}"')
    conn.commit()

    flash("Статус заявки обновлён.", "success")
    return redirect(url_for('manager_dashboard'))

@app.route('/assign_executor/<int:app_id>', methods=['POST'])
def assign_executor(app_id):
    user_id = request.form['User_ID']

    conn = get_db_connection()
    cursor = conn.cursor()

    # Проверка: уже назначен?
    cursor.execute("""
        SELECT COUNT(*) FROM ApplicationAssignments
        WHERE Application_ID = ? AND User_ID = ?
    """, (app_id, user_id))
    if cursor.fetchone()[0] == 0:
        cursor.execute("""
            INSERT INTO ApplicationAssignments (Application_ID, User_ID)
            VALUES (?, ?)
        """, (app_id, user_id))
        flash("Исполнитель успешно назначен.", "success")
    else:
        flash("Этот сотрудник уже назначен на заявку.", "warning")

    conn.commit()
    return redirect(url_for('manager_dashboard'))

@app.route('/unassign_executor/<int:app_id>/<int:user_id>', methods=['POST'])
def unassign_executor(app_id, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM ApplicationAssignments
        WHERE Application_ID = ? AND User_ID = ?
    """, (app_id, user_id))

    conn.commit()
    flash('Исполнитель откреплён.', 'info')
    return redirect(url_for('manager_dashboard'))

if __name__ == '__main__':
    app.run(debug=True)
    print("Приложение запущено! Перейдите по ссылке: http://127.0.0.1:5000/")
