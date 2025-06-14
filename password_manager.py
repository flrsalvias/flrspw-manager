import os
import json
import base64
from datetime import datetime
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog, ttk
from cryptography.fernet import Fernet
import pyperclip

PASSWORDS_FILE = "passwords.json"
MASTER_KEY_FILE = "master.key"
AUTOSAVE_INTERVAL_MS = 30000

def derive_key_from_password(password):
    return base64.urlsafe_b64encode(password.encode().ljust(32)[:32])

def load_passwords(fernet):
    if not os.path.exists(PASSWORDS_FILE):
        return {}
    try:
        with open(PASSWORDS_FILE, "rb") as f:
            data = fernet.decrypt(f.read())
            return json.loads(data)
    except Exception:
        raise ValueError("Fichier corrompu ou mot de passe incorrect.")

def save_passwords(data, fernet):
    with open(PASSWORDS_FILE, "wb") as f:
        f.write(fernet.encrypt(json.dumps(data).encode()))

def format_date(s):
    return datetime.strptime(s, "%Y-%m-%d %H:%M:%S").strftime("%d/%m/%Y %H:%M") if s else ""

def generate_password(length=12):
    import string, random
    chars = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))

class PasswordManagerApp:
    def __init__(self, root, fernet):
        self.root = root
        self.fernet = fernet
        self.passwords = {}
        try:
            self.passwords = load_passwords(fernet)
        except ValueError:
            if messagebox.askyesno("Erreur", "Fichier corrompu. Réinitialiser ?"):
                os.remove(MASTER_KEY_FILE)
                os.remove(PASSWORDS_FILE)
                messagebox.showinfo("Redémarrage", "Relancez l'application.")
                root.destroy()
                return
            else:
                root.destroy()
                return

        self.current_theme = "light"
        self.sort_ascending = True

        self.root.title("Gestionnaire de mots de passe")
        self.build_ui()
        self.update_listbox()
        self.apply_theme()
        self.autosave()

    def build_ui(self):
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.update_listbox())

        self.category_filter_var = tk.StringVar()
        self.category_var = tk.StringVar()
        self.service_var = tk.StringVar()
        self.password_var = tk.StringVar()

        search_frame = tk.Frame(self.root)
        search_frame.pack(fill=tk.X, padx=5, pady=5)

        tk.Entry(search_frame, textvariable=self.search_var, width=30).pack(side=tk.LEFT, padx=(0, 5))

        self.category_filter_menu = ttk.Combobox(search_frame, textvariable=self.category_filter_var, state="readonly")
        self.category_filter_menu.pack(side=tk.LEFT)
        self.category_filter_menu.bind("<<ComboboxSelected>>", lambda e: self.update_listbox())

        tk.Button(search_frame, text="🔃 Trier", command=self.toggle_sort).pack(side=tk.RIGHT)

        self.listbox = tk.Listbox(self.root, height=10)
        self.listbox.pack(fill=tk.BOTH, expand=True, padx=5, pady=(0, 5))
        self.listbox.bind("<<ListboxSelect>>", self.on_listbox_select)

        form = tk.Frame(self.root)
        form.pack(padx=5, pady=5)

        tk.Label(form, text="Service:").grid(row=0, column=0, sticky="e")
        tk.Entry(form, textvariable=self.service_var).grid(row=0, column=1, sticky="we", padx=5)

        tk.Label(form, text="Mot de passe:").grid(row=1, column=0, sticky="e")
        self.entry_password = tk.Entry(form, textvariable=self.password_var, show="*")
        self.entry_password.grid(row=1, column=1, sticky="we", padx=5)
        self.entry_password.bind("<Enter>", self.show_password)
        self.entry_password.bind("<Leave>", self.hide_password)

        tk.Label(form, text="Catégorie:").grid(row=2, column=0, sticky="e")
        self.entry_category = tk.Entry(form, textvariable=self.category_var)
        self.entry_category.grid(row=2, column=1, sticky="we", padx=5)

        form.columnconfigure(1, weight=1)

        self.history_text = tk.Text(self.root, height=4, state="disabled")
        self.history_text.pack(fill=tk.X, padx=5, pady=5)

        button_frame1 = tk.Frame(self.root)
        button_frame1.pack(padx=5, pady=(5, 2))
        for i, (label, cmd) in enumerate([
            ("💾 Sauvegarder", self.save_password),
            ("📋 Copier", self.copy_password),
            ("🔑 Générer", self.generate_password_gui),
            ("🗑️ Supprimer", self.delete_password),
        ]):
            tk.Button(button_frame1, text=label, command=cmd, width=12).grid(row=0, column=i, padx=2)

        button_frame2 = tk.Frame(self.root)
        button_frame2.pack(padx=5, pady=(2, 5))
        for i, (label, cmd) in enumerate([
            ("📁 Importer", self.import_json),
            ("📤 Exporter", self.export_json),
            ("🌓 Thème", self.toggle_theme),
        ]):
            tk.Button(button_frame2, text=label, command=cmd, width=12).grid(row=0, column=i, padx=2)

    def toggle_sort(self):
        self.sort_ascending = not self.sort_ascending
        self.update_listbox()

    def apply_theme(self):
        bg = "#1e1e1e" if self.current_theme == "dark" else "white"
        fg = "#f0f0f0" if self.current_theme == "dark" else "black"
        widgets = self.root.winfo_children()
        for widget in widgets:
            try:
                widget.config(bg=bg, fg=fg)
            except:
                pass
        self.root.config(bg=bg)

    def toggle_theme(self):
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        self.apply_theme()

    def update_listbox(self):
        self.listbox.delete(0, tk.END)
        search = self.search_var.get().lower()
        selected_category = self.category_filter_var.get()
        all_categories = set()
        items = []
        for name, entry in self.passwords.items():
            cat = entry.get("category", "")
            all_categories.add(cat)
            if search in name.lower() and (not selected_category or cat == selected_category):
                items.append((name, cat))

        items.sort(key=lambda x: x[0], reverse=not self.sort_ascending)
        for name, _ in items:
            self.listbox.insert(tk.END, name)

        self.category_filter_menu["values"] = [""] + sorted(all_categories)

    def on_listbox_select(self, event):
        if not self.listbox.curselection():
            return
        service = self.listbox.get(self.listbox.curselection())
        entry = self.passwords.get(service)
        self.service_var.set(service)
        self.password_var.set(entry["password"])
        self.category_var.set(entry.get("category", ""))
        self.show_history(entry.get("history", []))

    def show_history(self, history):
        self.history_text.config(state="normal")
        self.history_text.delete("1.0", tk.END)
        for h in history:
            self.history_text.insert(tk.END, f"{format_date(h)}\n")
        self.history_text.config(state="disabled")

    def clear_fields(self):
        self.service_var.set("")
        self.password_var.set("")
        self.category_var.set("")

    def copy_password(self):
        pwd = self.password_var.get()
        if not pwd:
            return
        pyperclip.copy(pwd)
        service = self.service_var.get()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if service in self.passwords:
            self.passwords[service]["last_copied"] = now
            self.passwords[service].setdefault("history", []).append(now)
            self.show_history(self.passwords[service]["history"])
        messagebox.showinfo("Info", "Mot de passe copié.")
        self.clear_fields()

    def save_password(self):
        service = self.service_var.get().strip()
        pwd = self.password_var.get().strip()
        cat = self.category_var.get().strip()
        if not service or not pwd:
            messagebox.showwarning("Erreur", "Champs requis.")
            return
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.passwords[service] = self.passwords.get(service, {
            "added": now,
            "last_copied": "",
            "history": []
        })
        self.passwords[service].update({
            "password": pwd,
            "category": cat
        })
        save_passwords(self.passwords, self.fernet)
        self.update_listbox()
        messagebox.showinfo("OK", "Mot de passe enregistré.")
        self.clear_fields()

    def delete_password(self):
        service = self.service_var.get()
        if service not in self.passwords:
            return
        if messagebox.askyesno("Suppression", f"Supprimer {service} ?"):
            del self.passwords[service]
            save_passwords(self.passwords, self.fernet)
            self.update_listbox()
            self.clear_fields()

    def generate_password_gui(self):
        length = simpledialog.askinteger("Longueur", "Longueur du mot de passe:", minvalue=8, maxvalue=64)
        if length:
            self.password_var.set(generate_password(length))

    def import_json(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        with open(path) as f:
            data = json.load(f)
        for k, v in data.items():
            self.passwords[k] = {
                "password": v,
                "added": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "last_copied": "",
                "history": [],
                "category": ""
            }
        save_passwords(self.passwords, self.fernet)
        self.update_listbox()

    def export_json(self):
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if not path:
            return
        data = {k: v["password"] for k, v in self.passwords.items()}
        with open(path, "w") as f:
            json.dump(data, f)

    def show_password(self, e):
        self.entry_password.config(show="")

    def hide_password(self, e):
        self.entry_password.config(show="*")

    def autosave(self):
        save_passwords(self.passwords, self.fernet)
        self.root.after(AUTOSAVE_INTERVAL_MS, self.autosave)

def main():
    root = tk.Tk()
    if os.path.exists(MASTER_KEY_FILE):
        with open(MASTER_KEY_FILE) as f:
            stored_key = f.read().strip()
    else:
        pwd = simpledialog.askstring("Création", "Créer mot de passe principal:", show="*")
        stored_key = derive_key_from_password(pwd).decode()
        with open(MASTER_KEY_FILE, "w") as f:
            f.write(stored_key)

    pwd = simpledialog.askstring("Connexion", "Mot de passe principal:", show="*")
    if not pwd:
        root.destroy()
        return
    fernet_key = derive_key_from_password(pwd).decode()
    if fernet_key != stored_key:
        if messagebox.askyesno("Erreur", "Mot de passe incorrect. Réinitialiser ?"):
            os.remove(MASTER_KEY_FILE)
            os.remove(PASSWORDS_FILE)
            messagebox.showinfo("OK", "Réinitialisé. Relancez l'application.")
        root.destroy()
        return

    fernet = Fernet(fernet_key.encode())
    app = PasswordManagerApp(root, fernet)
    root.mainloop()

if __name__ == "__main__":
    main()
