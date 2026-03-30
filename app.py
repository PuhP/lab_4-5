import re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user

# Импортируем наши расширения и модели
from extensions import db
from models import Role, User, VisitLog

app = Flask(__name__)
app.config['SECRET_KEY'] = 'lab5-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Инициализируем БД
db.init_app(app)

# --- ВАЛИДАЦИЯ ПАРОЛЯ ---
def validate_password(password):
    errors = []
    if not (8 <= len(password) <= 128):
        errors.append("Длина должна быть от 8 до 128 символов.")
    if not re.search(r'[a-zа-я]', password):
        errors.append("Должна быть минимум одна строчная буква.")
    if not re.search(r'[A-ZА-Я]', password):
        errors.append("Должна быть минимум одна заглавная буква.")
    if not re.search(r'\d', password):
        errors.append("Должна быть минимум одна цифра.")
    if ' ' in password:
        errors.append("Пароль не должен содержать пробелы.")
    return errors

# --- ИНИЦИАЛИЗАЦИЯ БД (Создание таблиц) ---
with app.app_context():
    db.create_all()
    if not Role.query.first():
        db.session.add_all([
            Role(name="Администратор", description="Полный доступ"),
            Role(name="Пользователь", description="Просмотр контента")
        ])
        db.session.commit()

# --- НАСТРОЙКА LOGIN MANAGER ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- ДЕКОРАТОР ПРОВЕРКИ ПРАВ ---
def check_rights(action):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
            
            user_role = current_user.role.name if current_user.role else None
            
            if user_role == "Администратор":
                return func(*args, **kwargs)
            
            if user_role == "Пользователь":
                user_id = kwargs.get('user_id')
                if action in ['view_user', 'edit_user'] and user_id == current_user.id:
                    return func(*args, **kwargs)
                if action == 'view_logs':
                    return func(*args, **kwargs)

            flash("У вас недостаточно прав для доступа к данной странице.", "danger")
            return redirect(url_for('index'))
        return wrapper
    return decorator

# --- АВТОМАТИЧЕСКОЕ ЛОГИРОВАНИЕ ---
@app.before_request
def log_visit():
    if not request.endpoint or request.endpoint == 'static': 
        return
    
    user_id = current_user.id if current_user.is_authenticated else None
    log = VisitLog(path=request.path, user_id=user_id)
    db.session.add(log)
    try:
        db.session.commit()
    except:
        db.session.rollback()

# --- МАРШРУТЫ (VIEWS) ---

@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/users/create', methods=['GET', 'POST'])
@login_required
@check_rights('create_user')
def create_user():
    roles = Role.query.all()
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        role_id = request.form.get('role_id')

        if not login or len(login) < 5 or not re.match(r'^[a-zA-Z0-9]+$', login):
            flash("Ошибка в логине (мин. 5 символов, латиница/цифры).", "danger")
            return render_template('create_user.html', roles=roles)

        password_errors = validate_password(password)
        if password_errors:
            for error in password_errors: flash(error, "danger")
            return render_template('create_user.html', roles=roles)

        if User.query.filter_by(login=login).first():
            flash("Логин занят.", "danger")
            return render_template('create_user.html', roles=roles)

        try:
            new_user = User(
                login=login,
                last_name=request.form.get('last_name'),
                first_name=first_name,
                middle_name=request.form.get('middle_name'),
                role_id=role_id if role_id else None
            )
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash("Пользователь создан!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f"Ошибка: {str(e)}", "danger")

    return render_template('create_user.html', roles=roles)

@app.route('/users/<int:user_id>')
@login_required
@check_rights('view_user')
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

@app.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@check_rights('edit_user')
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    roles = Role.query.all()
    
    if request.method == 'POST':
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.middle_name = request.form.get('middle_name')
        
        if current_user.role.name == "Администратор":
            user.role_id = request.form.get('role_id')

        try:
            db.session.commit()
            flash("Данные обновлены!", "success")
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f"Ошибка: {str(e)}", "danger")

    return render_template('edit_user.html', user=user, roles=roles)

@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@check_rights('delete_user')
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Нельзя удалить самого себя!", "danger")
        return redirect(url_for('index'))
    db.session.delete(user)
    db.session.commit()
    flash("Удалено.", "success")
    return redirect(url_for('index'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(login=request.form.get('login')).first()
        if user and user.check_password(request.form.get('password')):
            login_user(user, remember=bool(request.form.get('remember')))
            flash("Успешный вход!", "success")
            return redirect(request.args.get('next') or url_for('index'))
        flash("Неверный логин или пароль.", "danger")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_pass = request.form.get('old_password')
        new_pass = request.form.get('new_password')
        if not current_user.check_password(old_pass):
            flash("Старый пароль неверен.", "danger")
        elif new_pass != request.form.get('confirm_password'):
            flash("Пароли не совпадают.", "danger")
        else:
            errors = validate_password(new_pass)
            if errors:
                for e in errors: flash(e, "danger")
            else:
                current_user.set_password(new_pass)
                db.session.commit()
                flash("Пароль изменен!", "success")
                return redirect(url_for('index'))
    return render_template('change_password.html')

# --- ЗАПУСК ---
if __name__ == '__main__':
    # Регистрация блюпринта журналов
    from auth_logs import logs_bp
    app.register_blueprint(logs_bp)
    
    app.run(debug=True)