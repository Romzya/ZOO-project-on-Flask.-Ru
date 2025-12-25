import sqlite3
from werkzeug.security import generate_password_hash

def init_db():
    conn = sqlite3.connect('zoo.db')
    cursor = conn.cursor()
    
    # Таблица пользователей
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        is_admin BOOLEAN DEFAULT FALSE
    )
    ''')
    
    # Таблица животных
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS animals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        species TEXT NOT NULL,
        age INTEGER,
        description TEXT,
        image_url TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Таблица мероприятий
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT,
        date TEXT NOT NULL,
        time TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Создаем тестового администратора (пароль: admin123)
    try:
        admin_hash = generate_password_hash('admin123')
        cursor.execute(
            "INSERT OR IGNORE INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)",
            ('admin', admin_hash, 'admin@zoo.com', True)
        )
    except:
        pass
    
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect('zoo.db')
    conn.row_factory = sqlite3.Row
    return conn

from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from database import init_db, get_db
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Замените на случайный секретный ключ
init_db()

# Декоратор для проверки авторизации администратора
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Требуется авторизация', 'error')
            return redirect(url_for('login'))
        
        db = get_db()
        user = db.execute('SELECT is_admin FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        db.close()
        
        if not user or not user['is_admin']:
            flash('Доступ запрещен. Требуются права администратора', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Главная страница
@app.route('/')
def index():
    db = get_db()
    # Получаем несколько животных для главной страницы
    animals = db.execute('SELECT * FROM animals ORDER BY id DESC LIMIT 3').fetchall()
    events = db.execute('SELECT * FROM events ORDER BY date LIMIT 3').fetchall()
    db.close()
    return render_template('index.html', animals=animals, events=events)

# Страница со всеми животными
@app.route('/animals')
def animals():
    db = get_db()
    animals = db.execute('SELECT * FROM animals ORDER BY name').fetchall()
    db.close()
    return render_template('animals.html', animals=animals)

# Страница мероприятий
@app.route('/events')
def events():
    db = get_db()
    events = db.execute('SELECT * FROM events ORDER BY date').fetchall()
    db.close()
    return render_template('events.html', events=events)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', '')
        is_admin = request.form.get('is_admin') == 'on'
        
        db = get_db()
        
        # Проверяем, существует ли пользователь
        existing_user = db.execute(
            'SELECT id FROM users WHERE username = ?', (username,)
        ).fetchone()
        
        if existing_user:
            flash('Пользователь с таким именем уже существует', 'error')
            db.close()
            return redirect(url_for('register'))
        
        # Хэшируем пароль
        hashed_password = generate_password_hash(password)
        
        # Сохраняем пользователя
        db.execute(
            'INSERT INTO users (username, password, email, is_admin) VALUES (?, ?, ?, ?)',
            (username, hashed_password, email, is_admin)
        )
        db.commit()
        db.close()
        
        flash('Регистрация успешна! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Авторизация
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ?', (username,)
        ).fetchone()
        db.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль', 'error')
    
    return render_template('login.html')

# Выход
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

# Админ-панель
@app.route('/admin')
@admin_required
def admin_panel():
    db = get_db()
    animals = db.execute('SELECT * FROM animals ORDER BY id DESC').fetchall()
    events = db.execute('SELECT * FROM events ORDER BY date').fetchall()
    users = db.execute('SELECT id, username, email, is_admin FROM users').fetchall()
    db.close()
    return render_template('admin.html', animals=animals, events=events, users=users)

# Добавление животного
@app.route('/admin/add_animal', methods=['GET', 'POST'])
@admin_required
def add_animal():
    if request.method == 'POST':
        name = request.form['name']
        species = request.form['species']
        age = request.form.get('age')
        description = request.form['description']
        image_url = request.form.get('image_url', '')
        
        db = get_db()
        db.execute(
            'INSERT INTO animals (name, species, age, description, image_url) VALUES (?, ?, ?, ?, ?)',
            (name, species, age, description, image_url)
        )
        db.commit()
        db.close()
        
        flash('Животное успешно добавлено', 'success')
        return redirect(url_for('admin_panel'))
    
    return render_template('add_animal.html')

# Добавление мероприятия
@app.route('/admin/add_event', methods=['GET', 'POST'])
@admin_required
def add_event():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        date = request.form['date']
        time = request.form['time']
        
        db = get_db()
        db.execute(
            'INSERT INTO events (title, description, date, time) VALUES (?, ?, ?, ?)',

(title, description, date, time)
        )
        db.commit()
        db.close()
        
        flash('Мероприятие успешно добавлено', 'success')
        return redirect(url_for('admin_panel'))
    
    return render_template('add_event.html')

# Удаление животного
@app.route('/admin/delete_animal/<int:animal_id>')
@admin_required
def delete_animal(animal_id):
    db = get_db()
    db.execute('DELETE FROM animals WHERE id = ?', (animal_id,))
    db.commit()
    db.close()
    flash('Животное удалено', 'success')
    return redirect(url_for('admin_panel'))

# Удаление мероприятия
@app.route('/admin/delete_event/<int:event_id>')
@admin_required
def delete_event(event_id):
    db = get_db()
    db.execute('DELETE FROM events WHERE id = ?', (event_id,))
    db.commit()
    db.close()
    flash('Мероприятие удалено', 'success')
    return redirect(url_for('admin_panel'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5522)