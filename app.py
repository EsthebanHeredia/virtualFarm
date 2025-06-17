from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import psycopg2
import psycopg2.extras
import hashlib
import os
from datetime import datetime, timedelta
from functools import wraps
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'tu_clave_secreta_muy_segura_aqui_12345')

# Configuración de la base de datos PostgreSQL
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    """Crea una conexión a la base de datos PostgreSQL"""
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True  # Similar a conn.commit() después de cada operación
    return conn

def get_db_cursor(conn):
    """Obtiene un cursor con nombre de columna"""
    return conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

def init_db():
    """Inicializa la base de datos con las tablas necesarias"""
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    
    # Tabla de usuarios
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de mensajes
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id SERIAL PRIMARY KEY,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            content TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Tabla de tareas compartidas
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tasks (
            id SERIAL PRIMARY KEY,
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS goals (
            id SERIAL PRIMARY KEY,
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
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS encrypted_letters (
            id SERIAL PRIMARY KEY,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            title TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            is_read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Insertar o actualizar usuarios por defecto
    davili_password = hashlib.sha256("Kayliteamo".encode()).hexdigest()
    kayli_password = hashlib.sha256("Daviliteamo".encode()).hexdigest()
    
    # En PostgreSQL, usar ON CONFLICT para hacer UPSERT
    cursor.execute('''
        INSERT INTO users (username, password_hash) VALUES (%s, %s)
        ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
    ''', ('davili', davili_password))
    
    cursor.execute('''
        INSERT INTO users (username, password_hash) VALUES (%s, %s)
        ON CONFLICT (username) DO UPDATE SET password_hash = EXCLUDED.password_hash
    ''', ('kayli', kayli_password))
    
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
    cursor = get_db_cursor(conn)
    five_days_ago = datetime.now() - timedelta(days=5)
    cursor.execute(
        'DELETE FROM messages WHERE created_at < %s',
        (five_days_ago.strftime('%Y-%m-%d %H:%M:%S'),)
    )
    conn.close()

def delete_old_completed_tasks():
    """Elimina tareas completadas con más de 5 días de antigüedad"""
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    five_days_ago = datetime.now() - timedelta(days=5)
    cursor.execute(
        'DELETE FROM tasks WHERE is_completed = TRUE AND modified_at < %s',
        (five_days_ago.strftime('%Y-%m-%d %H:%M:%S'),)
    )
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
        cursor = get_db_cursor(conn)
        cursor.execute(
            'SELECT * FROM users WHERE username = %s AND password_hash = %s',
            (username, hash_password(password))
        )
        user = cursor.fetchone()
        conn.close()
        
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
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
    cursor = get_db_cursor(conn)
    
    # Contar mensajes no leídos
    cursor.execute(
        'SELECT COUNT(*) as count FROM messages WHERE receiver = %s AND is_read = FALSE',
        (session['username'],)
    )
    unread_messages = cursor.fetchone()['count']
    
    # Contar cartas no leídas
    cursor.execute(
        'SELECT COUNT(*) as count FROM encrypted_letters WHERE receiver = %s AND is_read = FALSE',
        (session['username'],)
    )
    unread_letters = cursor.fetchone()['count']
    
    # Contar tareas pendientes
    cursor.execute(
        'SELECT COUNT(*) as count FROM tasks WHERE is_completed = FALSE'
    )
    pending_tasks = cursor.fetchone()['count']
    
    # Contar metas pendientes
    cursor.execute(
        'SELECT COUNT(*) as count FROM goals WHERE is_completed = FALSE'
    )
    pending_goals = cursor.fetchone()['count']
    
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
    cursor = get_db_cursor(conn)
    
    # Obtener todos los mensajes para el usuario actual
    cursor.execute(
        'SELECT * FROM messages WHERE receiver = %s ORDER BY created_at DESC',
        (session['username'],)
    )
    received_messages = cursor.fetchall()
    
    # Obtener mensajes enviados
    cursor.execute(
        'SELECT * FROM messages WHERE sender = %s ORDER BY created_at DESC',
        (session['username'],)
    )
    sent_messages = cursor.fetchall()
    
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
    cursor = get_db_cursor(conn)
    cursor.execute(
        'INSERT INTO messages (sender, receiver, content) VALUES (%s, %s, %s)',
        (session['username'], receiver, content)
    )
    conn.close()
    
    flash('Mensaje enviado correctamente', 'success')
    return redirect(url_for('messages'))

@app.route('/mark_message_read/<int:message_id>')
@login_required
def mark_message_read(message_id):
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute(
        'UPDATE messages SET is_read = TRUE WHERE id = %s AND receiver = %s',
        (message_id, session['username'])
    )
    conn.close()
    
    return redirect(url_for('messages'))

@app.route('/delete_message/<int:message_id>', methods=['POST'])
@login_required
def delete_message(message_id):
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    # Solo permite borrar si el usuario es el receptor o el emisor
    cursor.execute(
        'DELETE FROM messages WHERE id = %s AND (receiver = %s OR sender = %s)',
        (message_id, session['username'], session['username'])
    )
    conn.close()
    flash('Mensaje eliminado correctamente', 'success')
    return redirect(url_for('messages'))

@app.route('/tasks')
@login_required
def tasks():
    # Borrar tareas completadas antiguas
    delete_old_completed_tasks()
    
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    # Ordenar primero por is_completed (las pendientes primero), luego por fecha de creación descendente
    cursor.execute(
        'SELECT * FROM tasks ORDER BY is_completed ASC, created_at DESC'
    )
    all_tasks = cursor.fetchall()
    conn.close()
    
    return render_template('tasks.html', tasks=all_tasks)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    title = request.form['title']
    description = request.form.get('description', '')
    
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute(
        'INSERT INTO tasks (title, description, created_by) VALUES (%s, %s, %s)',
        (title, description, session['username'])
    )
    conn.close()
    
    flash('Tarea agregada correctamente', 'success')
    return redirect(url_for('tasks'))

@app.route('/toggle_task/<int:task_id>')
@login_required
def toggle_task(task_id):
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute('SELECT * FROM tasks WHERE id = %s', (task_id,))
    task = cursor.fetchone()
    
    new_status = not task['is_completed']
    cursor.execute(
        'UPDATE tasks SET is_completed = %s, modified_by = %s, modified_at = %s WHERE id = %s',
        (new_status, session['username'], datetime.now(), task_id)
    )
    conn.close()
    
    return redirect(url_for('tasks'))

@app.route('/delete_task/<int:task_id>', methods=['POST'])
@login_required
def delete_task(task_id):
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    # Eliminar la tarea si existe
    cursor.execute('DELETE FROM tasks WHERE id = %s', (task_id,))
    conn.close()
    flash('Tarea eliminada correctamente', 'success')
    return redirect(url_for('tasks'))

@app.route('/goals')
@login_required
def goals():
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute(
        'SELECT * FROM goals ORDER BY created_at DESC'
    )
    all_goals = cursor.fetchall()
    conn.close()
    
    return render_template('goals.html', goals=all_goals)

@app.route('/add_goal', methods=['POST'])
@login_required
def add_goal():
    title = request.form['title']
    description = request.form.get('description', '')
    
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute(
        'INSERT INTO goals (title, description, created_by) VALUES (%s, %s, %s)',
        (title, description, session['username'])
    )
    conn.close()
    
    flash('Meta agregada correctamente', 'success')
    return redirect(url_for('goals'))

@app.route('/toggle_goal/<int:goal_id>')
@login_required
def toggle_goal(goal_id):
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute('SELECT * FROM goals WHERE id = %s', (goal_id,))
    goal = cursor.fetchone()
    
    new_status = not goal['is_completed']
    cursor.execute(
        'UPDATE goals SET is_completed = %s, modified_by = %s, modified_at = %s WHERE id = %s',
        (new_status, session['username'], datetime.now(), goal_id)
    )
    conn.close()
    
    return redirect(url_for('goals'))

@app.route('/delete_goal/<int:goal_id>', methods=['POST'])
@login_required
def delete_goal(goal_id):
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute('DELETE FROM goals WHERE id = %s', (goal_id,))
    conn.close()
    flash('Meta eliminada correctamente', 'success')
    return redirect(url_for('goals'))

@app.route('/encrypted_letters')
@login_required
def encrypted_letters():
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    
    # Obtener cartas recibidas
    cursor.execute(
        'SELECT * FROM encrypted_letters WHERE receiver = %s ORDER BY created_at DESC',
        (session['username'],)
    )
    received_letters = cursor.fetchall()
    
    # Obtener cartas enviadas
    cursor.execute(
        'SELECT * FROM encrypted_letters WHERE sender = %s ORDER BY created_at DESC',
        (session['username'],)
    )
    sent_letters = cursor.fetchall()
    
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
        cursor = get_db_cursor(conn)
        cursor.execute(
            'INSERT INTO encrypted_letters (sender, receiver, title, encrypted_content) VALUES (%s, %s, %s, %s)',
            (session['username'], receiver, title, encrypted_content)
        )
        conn.close()
        
        flash('Carta enviada correctamente', 'success')
        return redirect(url_for('encrypted_letters'))
    
    return render_template('create_letter.html')

@app.route('/mark_letter_read/<int:letter_id>', methods=['POST'])
@login_required
def mark_letter_read(letter_id):
    conn = get_db_connection()
    cursor = get_db_cursor(conn)
    cursor.execute(
        'UPDATE encrypted_letters SET is_read = TRUE WHERE id = %s AND receiver = %s',
        (letter_id, session['username'])
    )
    conn.close()
    
    flash('Carta marcada como leída', 'success')
    return redirect(url_for('encrypted_letters'))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)
