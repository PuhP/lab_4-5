import csv
import io
from flask import Blueprint, render_template, request, send_file, flash, redirect, url_for
from flask_login import login_required, current_user
from sqlalchemy import func

# Импортируем db и модели из новых файлов
from extensions import db
from models import VisitLog, User

logs_bp = Blueprint('logs', __name__)

@logs_bp.route('/logs')
@login_required
def view_logs():
    # Проверка прав (Админ видит всё, Пользователь — только своё)
    if current_user.role.name not in ["Администратор", "Пользователь"]:
        flash("У вас недостаточно прав для просмотра журналов.", "danger")
        return redirect(url_for('index'))

    page = request.args.get('page', 1, type=int)
    
    if current_user.role.name == "Администратор":
        query = VisitLog.query.order_by(VisitLog.created_at.desc())
    else:
        query = VisitLog.query.filter_by(user_id=current_user.id).order_by(VisitLog.created_at.desc())
        
    pagination = query.paginate(page=page, per_page=10)
    return render_template('logs.html', pagination=pagination)

@logs_bp.route('/reports/pages')
@login_required
def report_pages():
    if current_user.role.name != "Администратор":
        flash("Только администратор может видеть отчеты.", "danger")
        return redirect(url_for('index'))

    # Группировка по путям (URL) и подсчет кликов
    stats = db.session.query(
        VisitLog.path, 
        func.count(VisitLog.id).label('count')
    ).group_by(VisitLog.path).order_by(func.count(VisitLog.id).desc()).all()
    
    return render_template('report_pages.html', stats=stats)

@logs_bp.route('/reports/users')
@login_required
def report_users():
    if current_user.role.name != "Администратор":
        flash("Только администратор может видеть отчеты.", "danger")
        return redirect(url_for('index'))

    # Статистика по пользователям (включая тех, кто ничего не посещал — outerjoin)
    stats = db.session.query(
        User.last_name, User.first_name, User.middle_name,
        func.count(VisitLog.id).label('count')
    ).outerjoin(VisitLog, User.id == VisitLog.user_id)\
     .group_by(User.id).order_by(func.count(VisitLog.id).desc()).all()
    
    return render_template('report_users.html', stats=stats)

@logs_bp.route('/reports/export/pages')
@login_required
def export_pages_csv():
    if current_user.role.name != "Администратор":
        return "Access Denied", 403

    stats = db.session.query(VisitLog.path, func.count(VisitLog.id)).group_by(VisitLog.path).all()
    
    # Генерация CSV в памяти
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['№', 'Страница', 'Количество посещений'])
    
    for i, row in enumerate(stats, 1):
        writer.writerow([i, row[0], row[1]])
    
    output.seek(0)
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8-sig')),
        mimetype='text/csv',
        as_attachment=True,
        download_name='report_pages.csv'
    )