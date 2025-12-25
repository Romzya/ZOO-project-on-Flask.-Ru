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