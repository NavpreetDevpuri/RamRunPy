from flask import Flask
from flask_socketio import SocketIO

app = Flask(__name__)
app.secret_key = "your_secret_key"
socketio = SocketIO(app, async_mode="eventlet")

with app.app_context():
    from routes import *

    # import eventlet

    # eventlet.monkey_patch()

if __name__ == "__main__":
    socketio.run(app, debug=True, host="0.0.0.0", port=5000, use_reloader=True)
