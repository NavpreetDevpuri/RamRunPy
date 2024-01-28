import sys
from flask import Flask, flash, redirect, render_template, session, request, url_for
from flask_socketio import SocketIO
import os
import encryption_helper
import threading

app = Flask(__name__)
app.secret_key = "your_secret_key"
socketio = SocketIO(app)

current_dir_path = os.path.dirname(__file__)
runners_dir_path = os.path.join(current_dir_path, "runners")
passwords_file_path = os.path.join(runners_dir_path, "passwords.txt")
os.makedirs(runners_dir_path, exist_ok=True)

# ... Other functions like get_stored_password_hashes, add_password_hash, etc. ...

from multiprocessing import Process, Queue

import os

# Global dictionary to keep track of script processes
script_processes = {}


def save_encrypted_logs():
    for filename, (_, queue) in script_processes.items():
        logs = []
        while not queue.empty():
            log_message = queue.get()
            logs.append(log_message)

        if logs:
            user_dir = get_user_directory(session["user_password"])
            log_file_path = os.path.join(user_dir, "log_" + filename)
            existing_logs = []

            if os.path.exists(log_file_path):
                with open(log_file_path, "rb") as log_file:
                    existing_logs = (
                        encryption_helper.decrypt_bytes(
                            log_file.read(), session["user_password"]
                        )
                        .decode()
                        .split("\n")
                    )

            all_logs = existing_logs + logs
            encrypted_logs = encryption_helper.encrypt_bytes(
                "\n".join(all_logs).encode(), session["user_password"]
            )

            with open(log_file_path, "wb") as log_file:
                log_file.write(encrypted_logs)


original_stdout = sys.stdout


def target(log_queue, script_path, password):
    with open(script_path, "rb") as file:
        script_content = encryption_helper.decrypt_bytes(file.read(), password).decode()

    sys.stdout = WriteToQueue(log_queue)
    exec(script_content, {"__builtins__": __builtins__})


def run_script_and_capture_output(filename, password, user_dir):
    global script_processes

    if filename in script_processes:
        process, _ = script_processes[filename]
        if process.is_alive():
            process.terminate()  # Terminate the existing process

    process_queue = Queue()
    script_path = os.path.join(user_dir, filename)
    process = Process(
        target=target,
        args=(process_queue, script_path, password),
    )
    process.start()
    script_processes[filename] = (process, process_queue)


class WriteToQueue:
    def __init__(self, queue):
        self.queue = queue

    def write(self, msg):
        socketio.emit("log_message", {"data": msg})
        temp_stdout = sys.stdout
        sys.stdout = original_stdout
        print(msg)
        sys.stdout = temp_stdout
        self.queue.put(msg)

    def flush(self):
        pass


def get_user_directory(password):
    password_hash = encryption_helper.hash_password(password)
    return os.path.join(runners_dir_path, password_hash)


@socketio.on("connect")
def handle_connect():
    print("Client connected")


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")


def get_stored_password_hashes():
    if os.path.exists(passwords_file_path):
        with open(passwords_file_path, "r") as file:
            return set(file.read().splitlines())
    return set()


def add_password_hash(password_hash):
    with open(passwords_file_path, "a") as file:
        file.write(password_hash + "\n")


def is_correct_password(password):
    password_hashes = get_stored_password_hashes()
    password_hash = encryption_helper.hash_password(password)

    if password_hash in password_hashes:
        return True
    else:
        # Create a new user-specific folder
        new_user_dir = os.path.join(runners_dir_path, password_hash)
        os.makedirs(new_user_dir, exist_ok=True)
        add_password_hash(password_hash)
        return True


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        password = request.form["password"]
        if is_correct_password(password):
            session["user_password"] = password
            return redirect(url_for("list_files"))
        else:
            flash("Login failed. Please try again.")
    return render_template("login.html")


@app.route("/list_files")
def list_files():
    if "user_password" not in session:
        return redirect(url_for("login"))
    password = session["user_password"]
    password_hash = encryption_helper.hash_password(password)
    user_dir = os.path.join(runners_dir_path, password_hash)

    files = os.listdir(user_dir)
    files = [encryption_helper.decrypt_filename(file, password) for file in files]

    return render_template("list_files.html", files=files)


@app.route("/logout")
def logout():
    session.pop("user_password", None)
    return redirect(url_for("login"))


@app.route("/add_file", methods=["GET", "POST"])
def add_file():
    if "user_password" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        filename = request.form["filename"]
        content = request.form["content"]
        password = session["user_password"]

        # Encrypt filename and content
        encrypted_filename = encryption_helper.encrypt_filename(filename, password)
        encrypted_content = encryption_helper.encrypt_bytes(content.encode(), password)

        # Save the encrypted file
        password_hash = encryption_helper.hash_password(password)
        user_dir = os.path.join(runners_dir_path, password_hash)
        with open(os.path.join(user_dir, encrypted_filename), "wb") as file:
            file.write(encrypted_content)

        run_script_and_capture_output(encrypted_filename, password, user_dir)
        return redirect(url_for("list_files"))

    return render_template("add_file.html")


@app.route("/edit_file/<filename>", methods=["GET", "POST"])
def edit_file(filename):
    if "user_password" not in session:
        return redirect(url_for("login"))

    password = session["user_password"]
    filename = encryption_helper.encrypt_filename(filename, password)
    password_hash = encryption_helper.hash_password(password)
    user_dir = os.path.join(runners_dir_path, password_hash)
    file_path = os.path.join(user_dir, filename)

    if request.method == "POST":
        # Save the edited content
        content = request.form["content"]
        encrypted_content = encryption_helper.encrypt_bytes(content.encode(), password)
        with open(file_path, "wb") as file:
            file.write(encrypted_content)
        run_script_and_capture_output(filename, password, user_dir)
        return redirect(url_for("list_files"))

    # Load the file content for editing
    with open(file_path, "rb") as file:
        encrypted_content = file.read()
    content = encryption_helper.decrypt_bytes(encrypted_content, password).decode()

    return render_template("edit_file.html", filename=filename, content=content)


@app.route("/delete_file/<filename>", methods=["POST"])
def delete_file(filename):
    if "user_password" not in session:
        return redirect(url_for("login"))

    password = session["user_password"]
    password_hash = encryption_helper.hash_password(password)
    user_dir = os.path.join(runners_dir_path, password_hash)
    file_path = os.path.join(user_dir, filename)

    # Delete the file
    os.remove(file_path)
    return redirect(url_for("list_files"))


@app.route("/start_script/<filename>")
def start_script(filename):
    if "user_password" not in session:
        return redirect(url_for("login"))

    password = session["user_password"]
    user_dir = get_user_directory(password)
    run_script_and_capture_output(filename, password, user_dir)
    return redirect(url_for("list_files"))


@app.route("/stop_script/<filename>")
def stop_script(filename):
    global script_processes

    if filename in script_processes:
        [process, _] = script_processes[filename]
        if process.is_alive():
            process.terminate()
        del script_processes[filename]

    return redirect(url_for("list_files"))


@app.route("/get_logs/<filename>")
def get_logs(filename):
    if "user_password" not in session:
        return redirect(url_for("login"))

    password = session["user_password"]
    user_dir = get_user_directory(password)
    log_file_path = os.path.join(user_dir, "log_" + filename)

    if os.path.exists(log_file_path):
        with open(log_file_path, "rb") as log_file:
            encrypted_logs = log_file.read()
        logs = encryption_helper.decrypt_bytes(encrypted_logs, password).decode()
        return logs
    return "No logs available."


if __name__ == "__main__":
    app.run(debug=True)
