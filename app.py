import os
import bcrypt
from functools import wraps
from flask import (Flask, render_template, redirect,
                   url_for, request, flash, session)
from flask_login import (LoginManager, UserMixin,
                         login_user, login_required,
                         logout_user, current_user)
from supabase import create_client, Client

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production")

# ── Supabase ──────────────────────────────────────────────

def get_sb() -> Client:
    return create_client(
        os.environ["SUPABASE_URL"],
        os.environ["SUPABASE_KEY"],
    )

# ── Flask-Login ───────────────────────────────────────────

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please log in to continue."
login_manager.login_message_category = "warning"


class User(UserMixin):
    def __init__(self, username: str, name: str, role: str):
        self.id   = username
        self.name = name
        self.role = role


@login_manager.user_loader
def load_user(username: str):
    try:
        res = get_sb().table("users").select("username,name,role") \
                      .eq("username", username).execute()
        if res.data:
            d = res.data[0]
            return User(d["username"], d["name"], d["role"])
    except Exception:
        pass
    return None


# ── Decorators ────────────────────────────────────────────

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if current_user.role != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("items"))
        return f(*args, **kwargs)
    return decorated


# ── Password helpers ──────────────────────────────────────

def hash_pw(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()


def check_pw(plain: str, stored: str) -> bool:
    """Supports both bcrypt hashes ($2b$) and plain text (migration)."""
    try:
        if stored.startswith("$2b$") or stored.startswith("$2a$"):
            return bcrypt.checkpw(plain.encode(), stored.encode())
        # Plain text fallback for existing records
        return plain == stored
    except Exception:
        return False


# ── Auth routes ───────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("items"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        try:
            res = get_sb().table("users").select("*") \
                          .eq("username", username).execute()
            user_data = res.data[0] if res.data else None
        except Exception as e:
            flash(f"Database error: {e}", "danger")
            return render_template("login.html")

        if user_data and check_pw(password, user_data["password"]):
            user = User(user_data["username"], user_data["name"], user_data["role"])
            login_user(user, remember=True)
            return redirect(request.args.get("next") or url_for("items"))
        else:
            flash("Incorrect username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ── Items ─────────────────────────────────────────────────

@app.route("/")
@app.route("/items")
@login_required
def items():
    search  = request.args.get("q", "").strip()
    bin_flt = request.args.get("bin_id", "").strip()

    try:
        # Supabase PostgREST join via foreign key
        items_res = get_sb().table("items") \
                            .select("*, bins(bin_name)") \
                            .order("item_id").execute()
        bins_res  = get_sb().table("bins").select("*").order("bin_id").execute()
        items_list = items_res.data or []
        bins_list  = bins_res.data  or []

        # Flatten nested bin_name from join
        for item in items_list:
            nested = item.pop("bins", None)
            item["bin_name"] = nested["bin_name"] if nested else "Unknown"

        # Server-side search
        if search:
            q = search.lower()
            items_list = [i for i in items_list if
                          q in i.get("item_name", "").lower() or
                          q in i.get("category", "").lower()]

        if bin_flt:
            items_list = [i for i in items_list if str(i.get("bin_id")) == bin_flt]

    except Exception as e:
        flash(f"Failed to load data: {e}", "danger")
        items_list, bins_list = [], []

    return render_template("items.html",
                           items=items_list,
                           bins=bins_list,
                           search=search,
                           bin_flt=bin_flt)


@app.route("/items/add", methods=["POST"])
@login_required
def add_item():
    item_name = request.form.get("item_name", "").strip()
    bin_id    = request.form.get("bin_id", "").strip()
    quantity  = request.form.get("quantity", "").strip()
    category  = request.form.get("category", "").strip()

    if not item_name or not bin_id:
        flash("Item name and bin are required.", "danger")
        return redirect(url_for("items"))

    try:
        get_sb().table("items").insert({
            "bin_id":    int(bin_id),
            "item_name": item_name,
            "quantity":  quantity,
            "category":  category,
        }).execute()
        flash(f"✅ '{item_name}' added!", "success")
    except Exception as e:
        flash(f"Failed to add item: {e}", "danger")

    return redirect(url_for("items"))


@app.route("/items/delete/<int:item_id>", methods=["POST"])
@login_required
def delete_item(item_id: int):
    try:
        get_sb().table("items").delete().eq("item_id", item_id).execute()
        flash("✅ Item deleted.", "success")
    except Exception as e:
        flash(f"Failed to delete: {e}", "danger")
    return redirect(url_for("items"))


# ── Bins ──────────────────────────────────────────────────

@app.route("/bins")
@login_required
def bins():
    try:
        bins_list = get_sb().table("bins").select("*").order("bin_id").execute().data or []
    except Exception as e:
        flash(f"Failed to load bins: {e}", "danger")
        bins_list = []
    return render_template("bins.html", bins=bins_list)


@app.route("/bins/add", methods=["POST"])
@login_required
def add_bin():
    bin_name = request.form.get("bin_name", "").strip()
    if not bin_name:
        flash("Bin name is required.", "danger")
        return redirect(url_for("bins"))
    try:
        get_sb().table("bins").insert({"bin_name": bin_name}).execute()
        flash(f"✅ Bin '{bin_name}' added!", "success")
    except Exception as e:
        flash(f"Failed to add bin: {e}", "danger")
    return redirect(url_for("bins"))


@app.route("/bins/rename", methods=["POST"])
@login_required
def rename_bin():
    bin_id   = request.form.get("bin_id", "").strip()
    new_name = request.form.get("new_name", "").strip()
    if not new_name or not bin_id:
        flash("Both bin and new name are required.", "danger")
        return redirect(url_for("bins"))
    try:
        get_sb().table("bins").update({"bin_name": new_name}) \
                .eq("bin_id", int(bin_id)).execute()
        flash("✅ Bin renamed!", "success")
    except Exception as e:
        flash(f"Failed to rename: {e}", "danger")
    return redirect(url_for("bins"))


@app.route("/bins/delete/<int:bin_id>", methods=["POST"])
@login_required
def delete_bin(bin_id: int):
    try:
        get_sb().table("bins").delete().eq("bin_id", bin_id).execute()
        flash("✅ Bin deleted (all its items too).", "success")
    except Exception as e:
        flash(f"Failed to delete bin: {e}", "danger")
    return redirect(url_for("bins"))


# ── Admin ─────────────────────────────────────────────────

@app.route("/admin")
@admin_required
def admin():
    try:
        users_list = get_sb().table("users") \
                             .select("username,name,email,role") \
                             .execute().data or []
    except Exception as e:
        flash(f"Failed to load users: {e}", "danger")
        users_list = []
    return render_template("admin.html", users=users_list)


@app.route("/admin/users/add", methods=["POST"])
@admin_required
def add_user():
    username = request.form.get("username", "").strip()
    name     = request.form.get("name", "").strip()
    email    = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    role     = request.form.get("role", "user")

    if not (username and name and password):
        flash("Username, name, and password are required.", "danger")
        return redirect(url_for("admin"))

    try:
        exists = get_sb().table("users").select("username") \
                         .eq("username", username).execute()
        if exists.data:
            flash("Username already exists.", "danger")
            return redirect(url_for("admin"))

        get_sb().table("users").insert({
            "username": username,
            "name":     name,
            "email":    email or f"{username}@example.com",
            "password": hash_pw(password),
            "role":     role,
        }).execute()
        flash(f"✅ User '{username}' created!", "success")
    except Exception as e:
        flash(f"Failed to create user: {e}", "danger")

    return redirect(url_for("admin"))


@app.route("/admin/users/delete/<username>", methods=["POST"])
@admin_required
def delete_user(username: str):
    if username == current_user.id:
        flash("You cannot delete your own account.", "danger")
        return redirect(url_for("admin"))
    try:
        get_sb().table("users").delete().eq("username", username).execute()
        flash(f"✅ User '{username}' deleted.", "success")
    except Exception as e:
        flash(f"Failed to delete user: {e}", "danger")
    return redirect(url_for("admin"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
