from flask import Flask, render_template, request
from flask_socketio import SocketIO, emit, join_room
from crypto import generate_rsa_keys, generate_aes_key, encrypt_aes_key_with_rsa, encrypt_message, decrypt_message

app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey'
socketio = SocketIO(app, cors_allowed_origins='*')

users = {}
aes_keys = {}

@app.route('/')
def index():
    return render_template('chat.html')

@socketio.on('register')
def handle_register(data):
    username = data['username']
    public_key = data['public_key']
    users[request.sid] = {'username': username, 'public_key': public_key}
    emit('registered', {'message': f'Welcome {username}!'})
    if len(users) == 2:
        sids = list(users.keys())
        aes_key = generate_aes_key()
        aes_keys['shared'] = aes_key
        for sid in sids:
            encrypted_key = encrypt_aes_key_with_rsa(aes_key, users[sid]['public_key'])
            socketio.emit('aes_key', {'encrypted_key': encrypted_key}, to=sid)
        socketio.emit('chat_ready', {'message': 'Both users connected. Chat is now secure!'})

@socketio.on('send_message')
def handle_message(data):
    sender = users[request.sid]['username']
    encrypted = data.get('encrypted_message', '')
    original = data.get('original', '')
    emit('receive_message', {
        'sender': sender,
        'encrypted': encrypted,
        'original': original
    }, broadcast=True)
    
@socketio.on('disconnect')
def handle_disconnect():
    if request.sid in users:
        del users[request.sid]

if __name__ == '__main__':
    socketio.run(app, debug=True, port=5000)