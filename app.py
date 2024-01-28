from flask import Flask, render_template, request, redirect, session, url_for, flash
import os
import encryption_helper

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this to a random secret key

current_dir_path = os.path.dirname(__file__)
runners_dir_path = os.path.join(current_dir_path, "runners")
passwords_file_path = os.path.join(runners_dir_path, "passwords.txt")
os.makedirs(runners_dir_path, exist_ok=True)


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


if __name__ == "__main__":
    app.run(debug=True)
