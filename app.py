from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import sqlite3
import hashlib
import os
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_muy_segura_aqui_12345'

# Configuración de la base de datos
DATABASE = 'database.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializa la base de datos con las tablas necesarias"""
    conn = get_db_connection()
    
    # Tabla de usuarios
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de mensajes
    conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            content TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de tareas compartidas
    conn.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            is_completed BOOLEAN DEFAULT FALSE,
            created_by TEXT NOT NULL,
            modified_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de metas de pareja
    conn.execute('''
        CREATE TABLE IF NOT EXISTS goals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            is_completed BOOLEAN DEFAULT FALSE,
            created_by TEXT NOT NULL,
            modified_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            modified_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de cartas cifradas
    conn.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_letters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            title TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insertar o actualizar usuarios por defecto
    davili_password = hashlib.sha256("davili123".encode()).hexdigest()
    kayli_password = hashlib.sha256("kayli123".encode()).hexdigest()
    
    conn.execute('''
        INSERT INTO users (username, password_hash) VALUES (?, ?)
        ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash
    ''', ('davili', davili_password))
    
    conn.execute('''
        INSERT INTO users (username, password_hash) VALUES (?, ?)
        ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash
    ''', ('kayli', kayli_password))
    
    conn.commit()
    # El bloque try-except sqlite3.IntegrityError ya no es necesario para estas inserciones específicas
    # ya que ON CONFLICT maneja la existencia de los usuarios.
    
    conn.close()

def hash_password(password):
    """Hashea una contraseña usando SHA-256"""
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    """Decorador para requerir login"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def delete_old_messages():
    """Elimina mensajes con más de 5 días de antigüedad"""
    conn = get_db_connection()
    five_days_ago = datetime.now() - timedelta(days=5)
    conn.execute(
        'DELETE FROM messages WHERE created_at < ?',
        (five_days_ago.strftime('%Y-%m-%d %H:%M:%S'),)
    )
    conn.commit()
    conn.close()

def delete_old_completed_tasks():
    """Elimina tareas completadas con más de 5 días de antigüedad"""
    conn = get_db_connection()
    five_days_ago = datetime.now() - timedelta(days=5)
    conn.execute(
        'DELETE FROM tasks WHERE is_completed = TRUE AND modified_at < ?',
        (five_days_ago.strftime('%Y-%m-%d %H:%M:%S'),)
    )
    conn.commit()
    conn.close()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute(
            'SELECT * FROM users WHERE username = ? AND password_hash = ?',
            (username, hash_password(password))
        ).fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            # flash(f'¡Bienvenido/a {username}!', 'success')  # Eliminado para no mostrar notificación de bienvenida
            return redirect(url_for('dashboard'))
        else:
            flash('Usuario o contraseña incorrectos', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Has cerrado sesión correctamente', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db_connection()
    
    # Contar mensajes no leídos
    unread_messages = conn.execute(
        'SELECT COUNT(*) as count FROM messages WHERE receiver = ? AND is_read = FALSE',
        (session['username'],)
    ).fetchone()['count']
    
    # Contar cartas no leídas
    unread_letters = conn.execute(
        'SELECT COUNT(*) as count FROM encrypted_letters WHERE receiver = ? AND is_read = FALSE',
        (session['username'],)
    ).fetchone()['count']
    
    # Contar tareas pendientes
    pending_tasks = conn.execute(
        'SELECT COUNT(*) as count FROM tasks WHERE is_completed = FALSE'
    ).fetchone()['count']
    
    # Contar metas pendientes
    pending_goals = conn.execute(
        'SELECT COUNT(*) as count FROM goals WHERE is_completed = FALSE'
    ).fetchone()['count']
    
    conn.close()
    
    return render_template('dashboard.html', 
                         unread_messages=unread_messages,
                         unread_letters=unread_letters,
                         pending_tasks=pending_tasks,
                         pending_goals=pending_goals)

@app.route('/messages')
@login_required
def messages():
    # Borrar mensajes antiguos antes de mostrar la bandeja
    delete_old_messages()
    conn = get_db_connection()
    
    # Obtener todos los mensajes para el usuario actual
    received_messages = conn.execute(
        'SELECT * FROM messages WHERE receiver = ? ORDER BY created_at DESC',
        (session['username'],)
    ).fetchall()
    
    # Obtener mensajes enviados
    sent_messages = conn.execute(
        'SELECT * FROM messages WHERE sender = ? ORDER BY created_at DESC',
        (session['username'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('messages.html', 
                         received_messages=received_messages,
                         sent_messages=sent_messages)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    content = request.form['content']
    receiver = 'kayli' if session['username'] == 'davili' else 'davili'
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)',
        (session['username'], receiver, content)
    )
    conn.commit()
    conn.close()
    
    flash('Mensaje enviado correctamente', 'success')
    return redirect(url_for('messages'))

@app.route('/mark_message_read/<int:message_id>')
@login_required
def mark_message_read(message_id):
    conn = get_db_connection()
    conn.execute(
        'UPDATE messages SET is_read = TRUE WHERE id = ? AND receiver = ?',
        (message_id, session['username'])
    )
    conn.commit()
    conn.close()
    
    return redirect(url_for('messages'))

@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    conn = get_db_connection()
    # Solo permite borrar si el usuario es el receptor o el emisor
    conn.execute(
        'DELETE FROM messages WHERE id = ? AND (receiver = ? OR sender = ?)',
        (message_id, session['username'], session['username'])
    )
    conn.commit()
    conn.close()
    flash('Mensaje eliminado correctamente', 'success')
    return redirect(url_for('messages'))

@app.route('/tasks')
@login_required
def tasks():
    # Borrar tareas completadas antiguas
    delete_old_completed_tasks()
    
    conn = get_db_connection()
    # Ordenar primero por is_completed (las pendientes primero), luego por fecha de creación descendente
    all_tasks = conn.execute(
        'SELECT * FROM tasks ORDER BY is_completed ASC, created_at DESC'
    ).fetchall()
    conn.close()
    
    return render_template('tasks.html', tasks=all_tasks)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    title = request.form['title']
    description = request.form.get('description', '')
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO tasks (title, description, created_by) VALUES (?, ?, ?)',
        (title, description, session['username'])
    )
    conn.commit()
    conn.close()
    
    flash('Tarea agregada correctamente', 'success')
    return redirect(url_for('tasks'))

@app.route('/toggle_task/<int:task_id>')
@login_required
def toggle_task(task_id):
    conn = get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ?', (task_id,)).fetchone()
    
    new_status = not task['is_completed']
    conn.execute(
        'UPDATE tasks SET is_completed = ?, modified_by = ?, modified_at = ? WHERE id = ?',
        (new_status, session['username'], datetime.now(), task_id)
    )
    conn.commit()
    conn.close()
    
    return redirect(url_for('tasks'))

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    conn = get_db_connection()
    # Eliminar la tarea si existe
    conn.execute('DELETE FROM tasks WHERE id = ?', (task_id,))
    conn.commit()
    conn.close()
    flash('Tarea eliminada correctamente', 'success')
    return redirect(url_for('tasks'))

@app.route('/goals')
@login_required
def goals():
    conn = get_db_connection()
    all_goals = conn.execute(
        'SELECT * FROM goals ORDER BY created_at DESC'
    ).fetchall()
    conn.close()
    
    return render_template('goals.html', goals=all_goals)

@app.route('/add_goal', methods=['POST'])
@login_required
def add_goal():
    title = request.form['title']
    description = request.form.get('description', '')
    
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO goals (title, description, created_by) VALUES (?, ?, ?)',
        (title, description, session['username'])
    )
    conn.commit()
    conn.close()
    
    flash('Meta agregada correctamente', 'success')
    return redirect(url_for('goals'))

@app.route('/toggle_goal/<int:goal_id>')
@login_required
def toggle_goal(goal_id):
    conn = get_db_connection()
    goal = conn.execute('SELECT * FROM goals WHERE id = ?', (goal_id,)).fetchone()
    
    new_status = not goal['is_completed']
    conn.execute(
        'UPDATE goals SET is_completed = ?, modified_by = ?, modified_at = ? WHERE id = ?',
        (new_status, session['username'], datetime.now(), goal_id)
    )
    conn.commit()
    conn.close()
    
    return redirect(url_for('goals'))

@app.route('/delete_goal/<int:goal_id>', methods=['POST'])
@login_required
def delete_goal(goal_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM goals WHERE id = ?', (goal_id,))
    conn.commit()
    conn.close()
    flash('Meta eliminada correctamente', 'success')
    return redirect(url_for('goals'))

@app.route('/encrypted_letters')
@login_required
def encrypted_letters():
    conn = get_db_connection()
    
    # Obtener cartas recibidas
    received_letters = conn.execute(
        'SELECT * FROM encrypted_letters WHERE receiver = ? ORDER BY created_at DESC',
        (session['username'],)
    ).fetchall()
    
    # Obtener cartas enviadas
    sent_letters = conn.execute(
        'SELECT * FROM encrypted_letters WHERE sender = ? ORDER BY created_at DESC',
        (session['username'],)
    ).fetchall()
    
    conn.close()
    
    return render_template('encrypted_letters.html', 
                         received_letters=received_letters,
                         sent_letters=sent_letters)

@app.route('/create_letter', methods=['GET', 'POST'])
@login_required
def create_letter():
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        receiver = 'kayli' if session['username'] == 'davili' else 'davili'
        
        # Por ahora guardamos el contenido sin cifrar (después integraremos RSA)
        encrypted_content = content  # Aquí iría el cifrado RSA
        
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO encrypted_letters (sender, receiver, title, encrypted_content) VALUES (?, ?, ?, ?)',
            (session['username'], receiver, title, encrypted_content)
        )
        conn.commit()
        conn.close()
        
        flash('Carta enviada correctamente', 'success')
        return redirect(url_for('encrypted_letters'))
    
    return render_template('create_letter.html')

@app.route('/mark_letter_read/<int:letter_id>', methods=['POST'])
@login_required
def mark_letter_read(letter_id):
    conn = get_db_connection()
    conn.execute(
        'UPDATE encrypted_letters SET is_read = TRUE WHERE id = ? AND receiver = ?',
        (letter_id, session['username'])
    )
    conn.commit()
    conn.close()
    
    flash('Carta marcada como leída', 'success')
    return redirect(url_for('encrypted_letters'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
