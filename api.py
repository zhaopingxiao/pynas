import sqlite3, werkzeug.security, time, random
tokens = {}

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        user_type TEXT NOT NULL
    );
    ''')

    cursor.execute('''
    INSERT INTO users (username, password, user_type)
    SELECT * FROM (
        VALUES ('admin', ?, 'admin')
    )
    WHERE NOT EXISTS (SELECT 1 FROM users);
    ''', (werkzeug.security.generate_password_hash('admin'),))

    conn.commit()

def token_close(lock):
    global tokens
    while True:
        time.sleep(1)
        
        with lock:
            current_tokens = list(tokens.items())
        
        token_del = []
        for k, v in current_tokens:
            with lock:
                if k not in tokens:
                    continue
                    
                tokens[k][1] -= 1
                if tokens[k][1] <= 0:
                    token_del.append(k)
        
        for v in token_del:
            with lock:
                if v in tokens:
                    del tokens[v]

def have_token(token, lock):
    with lock:
        if token in tokens:
            return True
        return False

def is_admin(token, lock):
    with lock:
        if token in tokens:
            username = tokens[token][0]
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('SELECT user_type FROM users WHERE username=?', (username,))
            user = cursor.fetchone()
            if not user or user[0] != 'admin':
                return False
            return True
        return False

def login(username, password, lock):
    with lock:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (username, ))
        user = cursor.fetchone()
        if user and werkzeug.security.check_password_hash(user[2], password):
            while True:
                token = ''.join([random.choice('1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ') for i in range(32)])
                if token not in tokens:
                    tokens[token] = [username, 60*60*24*7]
                    return token
        return None

def logout(token, lock):
    with lock:
        if token in tokens:
            del tokens[token]

def add_user(username, password, role, lock):
    with lock:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        if cursor.fetchone():
            return False
        hashed_password = werkzeug.security.generate_password_hash(password)
        cursor.execute('INSERT INTO users (username, password, user_type) VALUES (?, ?, ?)', (username, hashed_password, role))
        conn.commit()
        return True
    
def delete_user(username, lock):
    with lock:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('DELETE FROM users WHERE username=?', (username,))
        conn.commit()
        return True
    
def change_password(username, new_password, lock):
    with lock:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        hashed_password = werkzeug.security.generate_password_hash(new_password)
        cursor.execute('UPDATE users SET password=? WHERE username=?', (hashed_password, username))
        conn.commit()
        return True
    
def get_users(lock):
    with lock:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT username, user_type FROM users')
        users = [{'username': row[0], 'role': row[1]} for row in cursor.fetchall()]
        return users
    
def admin_count(lock):
    with lock:
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM users WHERE user_type=?', ('admin',))
        admin_count = cursor.fetchone()[0]
        return admin_count
