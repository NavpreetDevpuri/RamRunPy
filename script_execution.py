import sys
import os
import encryption_helper
from multiprocessing import Process, Queue
from app import socketio
from utils import runners_dir_path

script_processes = {}

main_stdout = sys.stdout


def background_runner(log_queue, script_filepath, password):
    with open(script_filepath, "rb") as file:
        script_content = encryption_helper.decrypt_bytes(file.read(), password).decode()
    script_dirpath = os.path.dirname(script_filepath)
    script_dirname = os.path.basename(script_dirpath)
    script_filename = os.path.basename(script_filepath)
    script_log_dirpath = os.path.join(runners_dir_path, "logs_" + script_dirname)
    os.makedirs(script_log_dirpath, exist_ok=True)
    script_log_filepath = os.path.join(script_log_dirpath, script_filename + ".logs")
    sys.stdout = WriteToQueue(log_queue, script_log_filepath, password)
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
        target=background_runner,
        args=(process_queue, script_path, password),
    )
    process.start()
    script_processes[filename] = (process, process_queue)


class WriteToQueue:
    def __init__(self, queue, log_filepath: str, password: str):
        self.queue = queue
        self.log_filepath = log_filepath
        self.password = password
        self.log_file = open(log_filepath, "a+")

    def write_to_log_file(self, log: str):
        encrypted_log = encryption_helper.encrypt_string(log, self.password)
        self.log_file.write(encrypted_log + "\n")
        self.log_file.flush()

    def print_to_main_process(self, log: str):
        temp_stdout = sys.stdout
        sys.stdout = main_stdout
        print(log, end="")
        sys.stdout = temp_stdout

    def write(self, log):
        self.write_to_log_file(log)
        self.print_to_main_process(log)
        self.queue.put(log)

    def flush(self):
        pass

    def __del__(self):
        self.log_file.flush()
        self.log_file.close()
