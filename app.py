"""Local password manager with a Google-Password-Manager-style Tkinter UI.  Run: python app.py"""
import hashlib
import tkinter as tk
from collections import Counter
from tkinter import messagebox, simpledialog, ttk

from generator import generate_password
from storage import Vault, VaultCorrupt, WrongPassword

BLUE, BLUE_DK, BLUE_LT = "#1a73e8", "#1765cc", "#e8f0fe"
BG, SIDE, BORDER = "#ffffff", "#f8f9fa", "#dadce0"
TEXT, GREY, RED = "#202124", "#5f6368", "#d93025"
FONT, FONT_B, FONT_H = ("Segoe UI", 10), ("Segoe UI", 10, "bold"), ("Segoe UI", 18)
AVATARS = ["#1a73e8", "#e8710a", "#188038", "#a142f4", "#d93025", "#12b5cb", "#e52592"]
AUTO_LOCK_MS, CLIP_CLEAR_MS = 5 * 60 * 1000, 30 * 1000


# ---------- helpers ----------
def btn(parent, text, cmd, primary=False, danger=False):
    fg = "white" if primary else (RED if danger else BLUE)
    return tk.Button(parent, text=text, command=cmd, relief="flat", bd=0, padx=14, pady=6,
                     cursor="hand2", font=FONT_B, bg=BLUE if primary else BG, fg=fg,
                     activebackground=BLUE_DK if primary else BLUE_LT,
                     activeforeground="white" if primary else fg)


def labeled_entry(parent, label, value="", show=""):
    tk.Label(parent, text=label, bg=BG, fg=GREY, font=FONT).pack(anchor="w", padx=28, pady=(10, 2))
    e = tk.Entry(parent, show=show, font=("Segoe UI", 11), relief="flat", highlightthickness=1,
                 highlightbackground=BORDER, highlightcolor=BLUE)
    e.insert(0, value or "")
    e.pack(fill="x", padx=28, ipady=6)
    return e


def make_dialog(master, title, w, h):
    d = tk.Toplevel(master)
    d.title(title)
    d.configure(bg=BG)
    d.transient(master.winfo_toplevel())
    x = master.winfo_rootx() + (master.winfo_width() - w) // 2
    y = master.winfo_rooty() + (master.winfo_height() - h) // 3
    d.geometry(f"{w}x{h}+{max(x, 0)}+{max(y, 0)}")
    d.resizable(False, False)
    d.grab_set()
    return d


def bind_tree(widget, seq, fn):
    widget.bind(seq, fn)
    for c in widget.winfo_children():
        bind_tree(c, seq, fn)


def is_weak(p):
    classes = sum(any(f(c) for c in p) for f in (str.islower, str.isupper, str.isdigit,
                                                 lambda c: not c.isalnum()))
    return len(p) < 12 or classes < 3


def find_issues(entries):
    counts = Counter(e["password"] for e in entries)
    out = {}
    for e in entries:
        iss = []
        if counts[e["password"]] > 1:
            iss.append("Reused password")
        if is_weak(e["password"]):
            iss.append("Weak password")
        out[e["id"]] = iss
    return out


# ---------- app ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Manager")
        self.geometry("980x640")
        self.minsize(760, 520)
        self.configure(bg=BG)
        self.vault = Vault()
        self.frame = None
        self._lock_job = self._clip_job = None
        for seq in ("<Key>", "<Button>", "<Motion>"):
            self.bind_all(seq, self._activity, add="+")
        self.protocol("WM_DELETE_WINDOW", self.quit_app)
        self.show_login()

    def _swap(self, frame):
        if self.frame:
            self.frame.destroy()
        self.frame = frame
        frame.pack(fill="both", expand=True)

    def show_login(self):
        self._swap(LoginFrame(self))

    def show_main(self):
        self._swap(MainFrame(self))
        self._activity()

    def lock(self):
        for w in self.winfo_children():
            if isinstance(w, tk.Toplevel):
                w.destroy()
        self.vault.lock()
        self.clear_clipboard()
        self.show_login()

    def quit_app(self):
        self.vault.lock()
        self.clear_clipboard()
        self.destroy()

    def _activity(self, _e=None):
        if self._lock_job:
            self.after_cancel(self._lock_job)
            self._lock_job = None
        if self.vault.unlocked:
            self._lock_job = self.after(AUTO_LOCK_MS, self.lock)

    def copy(self, text, what="Copied"):
        self.clipboard_clear()
        self.clipboard_append(text)
        self._clip_text = text
        if self._clip_job:
            self.after_cancel(self._clip_job)
        self._clip_job = self.after(CLIP_CLEAR_MS, self.clear_clipboard)
        self.toast(f"{what}. Clipboard clears in {CLIP_CLEAR_MS // 1000}s")

    def clear_clipboard(self):
        text = getattr(self, "_clip_text", None)
        if text is None:
            return
        try:
            if self.clipboard_get() == text:  # only clear if we still own it
                self.clipboard_clear()
                self.clipboard_append("")
        except tk.TclError:
            pass
        self._clip_text = None

    def toast(self, msg):
        t = tk.Label(self, text=msg, bg=TEXT, fg="white", padx=16, pady=8, font=FONT)
        t.place(relx=0.5, rely=0.96, anchor="s")
        self.after(2500, t.destroy)


# ---------- login ----------
class LoginFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app, bg=SIDE)
        self.app, self.fails = app, 0
        self.new = not app.vault.exists()
        card = tk.Frame(self, bg=BG, highlightbackground=BORDER, highlightthickness=1)
        card.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(card, text="🔐", font=("Segoe UI", 34), bg=BG).pack(pady=(28, 0), padx=60)
        tk.Label(card, text="Create your vault" if self.new else "Welcome back",
                 font=FONT_H, bg=BG, fg=TEXT).pack(pady=(4, 2))
        tk.Label(card, text="Choose a strong master password. It cannot be recovered." if self.new
                 else "Enter your master password to unlock", bg=BG, fg=GREY, font=FONT).pack()
        self.pw = labeled_entry(card, "Master password", show="•")
        self.pw2 = labeled_entry(card, "Confirm master password", show="•") if self.new else None
        self.msg = tk.Label(card, text="", fg=RED, bg=BG, font=FONT)
        self.msg.pack(pady=(8, 0))
        self.go = btn(card, "Create vault" if self.new else "Unlock", self.submit, primary=True)
        self.go.pack(fill="x", padx=28, pady=(8, 28))
        for e in (self.pw, self.pw2):
            if e:
                e.bind("<Return>", lambda _e: self.submit())
        self.pw.focus_set()

    def submit(self):
        p = self.pw.get()
        v = self.app.vault
        try:
            if self.new:
                if len(p) < 8:
                    return self.msg.config(text="Use at least 8 characters (12+ recommended).")
                if p != self.pw2.get():
                    return self.msg.config(text="Passwords do not match.")
                v.create(p)
            else:
                v.unlock(p)
        except WrongPassword:
            self.fails += 1
            self.msg.config(text="Incorrect master password.")
            self.pw.delete(0, "end")
            self.go.config(state="disabled")  # growing delay after failures
            self.after(min(2 ** self.fails, 30) * 500, lambda: self.go.config(state="normal"))
        except VaultCorrupt as ex:
            self.msg.config(text=str(ex))
        else:
            self.app.show_main()


# ---------- main window ----------
class MainFrame(tk.Frame):
    def __init__(self, app):
        super().__init__(app, bg=BG)
        self.app, self.vault, self.mode = app, app.vault, "all"

        side = tk.Frame(self, bg=SIDE, width=230)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="🔑 Password Manager", font=("Segoe UI", 13), bg=SIDE, fg=TEXT)\
            .pack(anchor="w", padx=20, pady=22)
        self.nav = {}
        for key, label in (("all", "🔑   Passwords"), ("check", "🛡   Checkup")):
            b = tk.Label(side, text=label, anchor="w", padx=20, pady=11, cursor="hand2", font=FONT_B)
            b.pack(fill="x", padx=(0, 12))
            b.bind("<Button-1>", lambda _e, k=key: self.set_mode(k))
            self.nav[key] = b
        tk.Frame(side, bg=SIDE).pack(expand=True)
        for text, cmd in (("Change master password", self.change_master), ("🔒  Lock vault", app.lock)):
            l = tk.Label(side, text=text, anchor="w", padx=20, pady=8, cursor="hand2", bg=SIDE, fg=GREY, font=FONT)
            l.pack(fill="x")
            l.bind("<Button-1>", lambda _e, c=cmd: c())
        tk.Frame(side, bg=SIDE, height=14).pack()

        main = tk.Frame(self, bg=BG)
        main.pack(side="left", fill="both", expand=True)
        top = tk.Frame(main, bg=BG)
        top.pack(fill="x", padx=28, pady=(20, 8))
        sbox = tk.Frame(top, bg="#f1f3f4")
        sbox.pack(side="left", fill="x", expand=True)
        tk.Label(sbox, text="🔍", bg="#f1f3f4").pack(side="left", padx=(12, 4))
        self.q = tk.StringVar()
        self.q.trace_add("write", lambda *_: self.refresh())
        tk.Entry(sbox, textvariable=self.q, font=("Segoe UI", 11), relief="flat", bg="#f1f3f4")\
            .pack(side="left", fill="x", expand=True, ipady=9)
        btn(top, "+  Add password", lambda: EntryDialog(self), primary=True).pack(side="left", padx=(14, 0))

        self.title = tk.Label(main, font=FONT_H, bg=BG, fg=TEXT)
        self.title.pack(anchor="w", padx=28, pady=(10, 6))
        tk.Frame(main, bg=BORDER, height=1).pack(fill="x", padx=28)

        area = tk.Frame(main, bg=BG)
        area.pack(fill="both", expand=True, padx=(28, 12))
        self.canvas = tk.Canvas(area, bg=BG, highlightthickness=0)
        sb = ttk.Scrollbar(area, command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.inner = tk.Frame(self.canvas, bg=BG)
        win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(win, width=e.width))
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.bind_all(seq, self._wheel, add="+")
        self.set_mode("all")

    def _wheel(self, e):
        if self.canvas.winfo_exists():
            d = -1 if e.num == 4 else 1 if e.num == 5 else (-1 if e.delta > 0 else 1)
            self.canvas.yview_scroll(d, "units")

    def set_mode(self, mode):
        self.mode = mode
        for k, b in self.nav.items():
            b.config(bg=BLUE_LT if k == mode else SIDE, fg=BLUE if k == mode else TEXT)
        self.refresh()

    def refresh(self):
        for w in self.inner.winfo_children():
            w.destroy()
        issues = find_issues(self.vault.entries)
        q = self.q.get().strip().lower()
        rows = [e for e in sorted(self.vault.entries, key=lambda e: e["site"].lower())
                if (not q or q in e["site"].lower() or q in e["username"].lower())
                and (self.mode == "all" or issues[e["id"]])]
        if self.mode == "all":
            self.title.config(text=f"Passwords ({len(rows)})")
        else:
            self.title.config(text=f"Checkup: {len(rows)} password(s) need attention")
        if not rows:
            msg = ("No passwords yet. Click “Add password” to save your first one."
                   if not self.vault.entries else
                   "Nothing to show." if self.mode == "all" else "🎉 All your passwords look good.")
            tk.Label(self.inner, text=msg, bg=BG, fg=GREY, font=FONT).pack(pady=60)
            return
        for e in rows:
            self._row(e, issues[e["id"]])

    def _row(self, e, iss):
        row = tk.Frame(self.inner, bg=BG, cursor="hand2")
        row.pack(fill="x")
        inner = tk.Frame(row, bg=BG)
        inner.pack(fill="x", pady=10)
        av = tk.Canvas(inner, width=40, height=40, bg=BG, highlightthickness=0)
        av.create_oval(2, 2, 38, 38, fill=AVATARS[int(hashlib.md5(e["site"].encode()).hexdigest(), 16) % len(AVATARS)], width=0)
        av.create_text(20, 20, text=(e["site"][:1] or "?").upper(), fill="white", font=("Segoe UI", 13, "bold"))
        av.pack(side="left", padx=(4, 14))
        col = tk.Frame(inner, bg=BG)
        col.pack(side="left", fill="x", expand=True)
        tk.Label(col, text=e["site"], bg=BG, fg=TEXT, font=FONT_B, anchor="w").pack(fill="x")
        tk.Label(col, text=e["username"] or "No username", bg=BG, fg=GREY, font=FONT, anchor="w").pack(fill="x")
        if iss:
            tk.Label(col, text="⚠ " + " · ".join(iss), bg=BG, fg=RED, font=("Segoe UI", 9), anchor="w").pack(fill="x")
        tk.Label(inner, text="••••••••••", bg=BG, fg=GREY).pack(side="right", padx=16)
        tk.Frame(self.inner, bg="#ebedef", height=1).pack(fill="x")
        bind_tree(row, "<Button-1>", lambda _e, en=e: DetailDialog(self, en))

    def change_master(self):
        p = self.winfo_toplevel()
        old = simpledialog.askstring("Change master password", "Current master password:", show="•", parent=p)
        if not old:
            return
        new = simpledialog.askstring("Change master password", "New master password (8+ chars):", show="•", parent=p)
        if not new or len(new) < 8:
            return messagebox.showwarning("Too short", "Use at least 8 characters.", parent=p) if new else None
        if simpledialog.askstring("Change master password", "Confirm new master password:", show="•", parent=p) != new:
            return messagebox.showerror("Mismatch", "Passwords did not match.", parent=p)
        try:
            self.vault.change_master(old, new)
            self.app.toast("Master password changed")
        except WrongPassword:
            messagebox.showerror("Error", "Current master password is incorrect.", parent=p)


# ---------- dialogs ----------
class DetailDialog:
    def __init__(self, main, entry):
        self.main, self.entry = main, entry
        d = self.d = make_dialog(main, entry["site"], 460, 430)
        tk.Label(d, text=entry["site"], font=FONT_H, bg=BG, fg=TEXT).pack(anchor="w", padx=28, pady=(22, 8))
        self._row("Username", entry["username"], False)
        self.pw_lbl = self._row("Password", entry["password"], True)
        if entry["notes"]:
            tk.Label(d, text="Notes", bg=BG, fg=GREY, font=FONT).pack(anchor="w", padx=28, pady=(12, 0))
            tk.Label(d, text=entry["notes"], bg=BG, fg=TEXT, font=FONT, wraplength=400, justify="left")\
                .pack(anchor="w", padx=28)
        tk.Label(d, text=f"Last modified {entry['modified'].replace('T', ' ')}", bg=BG, fg=GREY,
                 font=("Segoe UI", 9)).pack(anchor="w", padx=28, pady=(14, 0))
        bar = tk.Frame(d, bg=BG)
        bar.pack(side="bottom", fill="x", padx=20, pady=18)
        btn(bar, "Delete", self.delete, danger=True).pack(side="left")
        btn(bar, "Edit", self.edit, primary=True).pack(side="right")
        btn(bar, "Close", d.destroy).pack(side="right", padx=8)

    def _row(self, label, value, secret):
        tk.Label(self.d, text=label, bg=BG, fg=GREY, font=FONT).pack(anchor="w", padx=28, pady=(10, 0))
        r = tk.Frame(self.d, bg=BG)
        r.pack(fill="x", padx=28)
        shown = "•" * 10 if secret else (value or "—")
        lbl = tk.Label(r, text=shown, bg=BG, fg=TEXT, font=("Segoe UI", 12))
        lbl.pack(side="left")
        btn(r, "Copy", lambda: self.main.app.copy(value, f"{label} copied")).pack(side="right")
        if secret:
            state = {"on": False}

            def toggle():
                state["on"] = not state["on"]
                lbl.config(text=value if state["on"] else "•" * 10)
                b.config(text="Hide" if state["on"] else "Show")
            b = btn(r, "Show", toggle)
            b.pack(side="right")
        return lbl

    def edit(self):
        self.d.destroy()
        EntryDialog(self.main, self.entry)

    def delete(self):
        if messagebox.askyesno("Delete password", f"Delete the saved password for {self.entry['site']}?", parent=self.d):
            self.main.vault.delete_entry(self.entry)
            self.main.refresh()
            self.d.destroy()


class EntryDialog:
    def __init__(self, main, entry=None):
        self.main, self.entry = main, entry
        d = self.d = make_dialog(main, "Edit password" if entry else "Add password", 460, 600)
        tk.Label(d, text="Edit password" if entry else "Add password", font=FONT_H, bg=BG, fg=TEXT)\
            .pack(anchor="w", padx=28, pady=(22, 4))
        g = (lambda k: entry[k]) if entry else (lambda k: "")
        self.site = labeled_entry(d, "Site or app", g("site"))
        self.user = labeled_entry(d, "Username / email", g("username"))
        self.pw = labeled_entry(d, "Password", g("password"), show="•")
        opts = tk.Frame(d, bg=BG)
        opts.pack(fill="x", padx=28, pady=(8, 0))
        self.show = tk.BooleanVar()
        tk.Checkbutton(opts, text="Show", variable=self.show, bg=BG, font=FONT,
                       command=lambda: self.pw.config(show="" if self.show.get() else "•")).pack(side="left")
        btn(opts, "Generate", self.generate).pack(side="right")
        gen = tk.Frame(d, bg=BG)
        gen.pack(fill="x", padx=28, pady=(4, 0))
        tk.Label(gen, text="Length", bg=BG, fg=GREY, font=FONT).pack(side="left")
        self.length = tk.IntVar(value=16)
        tk.Spinbox(gen, from_=8, to=64, width=4, textvariable=self.length).pack(side="left", padx=(6, 12))
        self.sym, self.dig = tk.BooleanVar(value=True), tk.BooleanVar(value=True)
        tk.Checkbutton(gen, text="Symbols", variable=self.sym, bg=BG, font=FONT).pack(side="left")
        tk.Checkbutton(gen, text="Digits", variable=self.dig, bg=BG, font=FONT).pack(side="left")
        tk.Label(d, text="Notes (optional)", bg=BG, fg=GREY, font=FONT).pack(anchor="w", padx=28, pady=(12, 2))
        self.notes = tk.Text(d, height=4, font=("Segoe UI", 10), relief="flat", highlightthickness=1,
                             highlightbackground=BORDER, highlightcolor=BLUE)
        self.notes.insert("1.0", g("notes"))
        self.notes.pack(fill="x", padx=28)
        bar = tk.Frame(d, bg=BG)
        bar.pack(side="bottom", fill="x", padx=20, pady=18)
        btn(bar, "Save", self.save, primary=True).pack(side="right")
        btn(bar, "Cancel", d.destroy).pack(side="right", padx=8)
        self.site.focus_set()

    def generate(self):
        try:
            p = generate_password(self.length.get(), symbols=self.sym.get(), digits=self.dig.get())
        except (ValueError, tk.TclError) as ex:
            return messagebox.showwarning("Cannot generate", str(ex), parent=self.d)
        self.pw.delete(0, "end")
        self.pw.insert(0, p)
        self.show.set(True)
        self.pw.config(show="")

    def save(self):
        site, pw = self.site.get().strip(), self.pw.get()
        if not site or not pw:
            return messagebox.showwarning("Missing info", "Site and password are required.", parent=self.d)
        f = dict(site=site, username=self.user.get().strip(), password=pw, notes=self.notes.get("1.0", "end").strip())
        if self.entry:
            self.main.vault.update_entry(self.entry, **f)
        else:
            self.main.vault.add_entry(**f)
        self.main.refresh()
        self.d.destroy()
        self.main.app.toast("Password saved")


if __name__ == "__main__":
    App().mainloop()
