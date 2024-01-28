import os
import encryption_helper

current_dir_path = os.path.dirname(__file__)
runners_dir_path = os.path.join(current_dir_path, "runners")
passwords_file_path = os.path.join(runners_dir_path, "passwords.txt")
os.makedirs(runners_dir_path, exist_ok=True)


def get_user_directory(password):
    password_hash = encryption_helper.hash_password(password)
    return os.path.join(runners_dir_path, password_hash)


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
