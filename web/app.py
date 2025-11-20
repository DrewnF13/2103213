from flask import Flask, render_template, request, redirect, url_for, session
import string

app = Flask(__name__)
app.secret_key = "supersecretkey"  # change in production


# -----------------------------
# Load Password Blacklist
# -----------------------------
def load_blacklist(path="blacklist.txt"):
    try:
        with open(path, "r") as f:
            return set(p.strip() for p in f.readlines() if p.strip())
    except FileNotFoundError:
        return set()

BLACKLIST = load_blacklist()


# -----------------------------
# OWASP Level-1 Password Validator + Blacklist Check
# -----------------------------
def is_valid_password(password: str, min_length: int = 8) -> bool:
    if not isinstance(password, str):
        return False

    if len(password) < min_length:
        return False

    # Reject if password is in blacklist
    if password in BLACKLIST:
        return False

    allowed_chars = string.printable
    for ch in password:
        if ch not in allowed_chars:
            return False

    return True


# -----------------------------
# Login Page
# -----------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        password = request.form.get("password", "")

        if not is_valid_password(password):
            return redirect(url_for("index"))

        session["password"] = password
        return redirect(url_for("welcome"))

    return render_template("index.html")


# -----------------------------
# Welcome Page
# -----------------------------
@app.route("/welcome")
def welcome():
    if "password" not in session:
        return redirect(url_for("index"))

    return render_template("welcome.html", password=session["password"])


# -----------------------------
# Logout
# -----------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
