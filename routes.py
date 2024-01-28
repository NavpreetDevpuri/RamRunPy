from app import app, socketio
from flask import flash, redirect, render_template, session, request, url_for
import os
import encryption_helper
from utils import is_correct_password, runners_dir_path, get_user_directory
from script_execution import run_script_and_capture_output
from script_execution import script_processes


@socketio.on("connect")
def handle_connect():
    print("Client connected")


@socketio.on("disconnect")
def handle_disconnect():
    print("Client disconnected")


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
        process, queue, background_task = script_processes[filename]
        if process.is_alive():
            process.kill()  # kill the existing process
            queue.put(None)
        del script_processes[filename]

    return redirect(url_for("list_files"))


@app.route("/get_logs/<filename>")
def get_logs(filename):
    if "user_password" not in session:
        return redirect(url_for("login"))

    password = session["user_password"]
    password_hash = encryption_helper.hash_password(password)
    log_dirpath = os.path.join(runners_dir_path, "logs_" + password_hash)
    log_file_path = os.path.join(log_dirpath, filename + ".logs")

    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as log_file:
            encrypted_logs = log_file.read().split("\n")[:-1]
        logs = [
            encryption_helper.decrypt_string(encrypted_log, password)
            for encrypted_log in encrypted_logs
        ]
        return logs
    return "No logs available."
