from flask import Flask, render_template, redirect, request, url_for, flash, session
import os
import pyotp

# Initialize the Flask app
app = Flask(__name__)

# Route for the home page
@app.route("/")
def home():
    # Render the 'home.html' template when visiting the root URL
    return render_template('home.html')

# Route for the login page (handles both GET and POST methods)
@app.route("/login", methods=['GET', 'POST'])
def login():
    # Capture the username and password from the submitted form (if POST request)
    form_user = request.form.get("username")
    form_pass = request.form.get("password")

    if request.method == 'POST':  # If the form is submitted via POST
        # Check if the submitted username and password match the ones in the app config
        if form_user == app.config["USER"] and form_pass == app.config["PASS"]:
            # If valid, save the username in the session and redirect to OTP authentication
            session['username'] = form_user
            # Redirect to OTP authentication step (assuming 2FA is enabled)
            return redirect(url_for("OTP_auth"))
        else:
            # If credentials are invalid, show a flash message and stay on the login page
            flash("Invalid credentials. Please try again.")
    
    # Redirect back to the home page if not POST (or if credentials are invalid)
    return redirect(url_for("home"))

# Route for OTP authentication (handles both GET and POST methods)
@app.route("/login/auth", methods=['GET', 'POST'])
def OTP_auth():
    # Check if the user is logged in (session must have a valid username)
    if session.get('username') is None:
        # If not logged in, redirect to the login page
        return redirect(url_for('login'))
    
    if request.method == 'POST':  # If the OTP form is submitted via POST
        # Create a TOTP (Time-based One-Time Password) instance with the secret key
        totp_instance = pyotp.TOTP(app.config["OTP_CODE"])
        # Verify the OTP entered by the user
        valid = totp_instance.verify(request.form.get("otp"))
        
        if valid:
            # If the OTP is valid, redirect to a success page
            return render_template("success.html")
        else:
            # If the OTP is invalid, show a flash message and stay on the authentication page
            flash("Invalid code. Please try again.")
    
    else:
        # If the OTP authentication hasn't been completed yet, check if OTP is enabled
        if app.config["OTP_ENABLED"] == "True":
            # If OTP is enabled, render the OTP authentication page
            return render_template('authentication.html')
        else:
            # If OTP is not enabled, enable it and render the page with the secret key
            app.config["OTP_ENABLED"] = "True"
            # Pass the generated OTP secret key to the template for the user
            return render_template('authentication.html', secret_key=app.config["OTP_CODE"])
    
    # Redirect to OTP authentication page if needed (catch-all fallback)
    return redirect(url_for("OTP_auth"))

# Main entry point for running the Flask application
if __name__ == "__main__":
    # Configuration settings for the application (username, password, OTP secret, etc.)
    app.config["USER"] = "wsu"  # Example username for login
    app.config["PASS"] = "gocougs"  # Example password for login
    app.config["OTP_CODE"] = pyotp.random_base32()  # Generate a random secret key for OTP
    app.config["OTP_ENABLED"] = "False"  # OTP is initially disabled
    app.config["SECRET_KEY"] = os.urandom(16).hex()  # Random 16-byte secret for session security
    
    # Run the app in debug mode
    app.run(debug=True)
