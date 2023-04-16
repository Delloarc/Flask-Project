from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
# For better password security
from werkzeug.security import generate_password_hash, check_password_hash
from . import db 
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint("auth", __name__)

@auth.route("/login", methods=["GET", "POST"])
def login():
    
    # When form is submitted
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
    
        # Return first result
        user = User.query.filter_by(email=email).first()
        # If user with email exists:
        if user:
            # If the password submitted in the form is right:
            if check_password_hash(user.password, password):
                flash("Erfolgreich angemeldet", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
            else:
                flash("Die eingegeben Daten sind inkorrekt", category="error")
        else:
            flash("Es wurde kein Konto mit dieser E-Mail-Adresse gefunden", category="error")


    return render_template("login.html", user=current_user)

@auth.route("/sign-up", methods=["GET", "POST"])
def sign_up():

    if request.method == "POST":

        name = request.form.get("name")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(email=email).first()

        if user:
            flash("Ein Konto mit dieser E-Mail-Adresse existiert bereits", category="error")
        elif password1 != password2:
            flash("Bitte wiederholen Sie das Passwort korrekt", category="error")
        elif len(name) < 2:
            flash("Bitte geben Sie Ihren vollständigen Namen ein", category="error")
        elif len(email) < 4:
            flash("Bitte geben Sie eine korrekte E-Mail-Adresse ein", category="error")
        elif len(password1) < 8 or len(password1) > 20:
            flash("Ihr Passwort muss zwischen 8 bis 20 Zeichen lang sein", category="error")
        else:
            new_user = User(email=email, name=name, password=generate_password_hash(password1, method="sha256"))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash("Erfolgreich registriert", category="success")

            return redirect(url_for("views.home"))

    return render_template("signup.html", user=current_user)