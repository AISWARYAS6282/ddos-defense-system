from flask_login import current_user
from flask_socketio import emit, disconnect
from ..extensions import socketio


@socketio.on('connect')
def on_connect():
    if not current_user.is_authenticated:
        disconnect()
        return False
    emit('connected', {
        'message': f'Welcome {current_user.username}',
        'role': current_user.role,
    })


@socketio.on('disconnect')
def on_disconnect():
    pass


@socketio.on('ping_server')
def on_ping(data):
    if not current_user.is_authenticated:
        disconnect(); return
    emit('pong_server', {'ts': data.get('ts')})
