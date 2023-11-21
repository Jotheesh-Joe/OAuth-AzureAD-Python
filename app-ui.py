import urllib
from flask import Flask, request, redirect, render_template, session, url_for, jsonify
import requests
import time
import os
from jwtdecode import validate_jwt, validate_jwt_auth
from flask_cors import CORS

app = Flask(__name__)
cors = CORS(app)
app.secret_key = '34ad45ty'  # Set a secure secret key for session management

# Azure AD application details
client_id = os.environ["CLIENT_ID"]
client_secret = os.environ["CLIENT_SECRET"]
redirect_uri = os.environ["REDIRECT_URL"]
tenant_id = os.environ["TENANT_ID"]
authorization_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/authorize"
token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/token"

valid_audiences = [client_id]
issuer = f'https://sts.windows.net/{tenant_id}/'


def is_token_valid():
    # Check if the access token exists and is not expired
    if validate_jwt_auth(session.get('id_token'), valid_audiences, issuer):
        return time.time() < session['token_expiration']
    return False


@app.route("/")
def index():
    if is_token_valid():
        return redirect(url_for('home'))  # Redirect authenticated users to the home page
    return render_template("index.html")  # Redirect unauthenticated users to the login page


@app.route("/home")
def home():
    if is_token_valid():
        # User is authenticated, show the home page
        return render_template("home.html", username=session.get('cds_id'))
    return render_template("index.html")


@app.route("/login")
def login():
    # Redirect the user to the Azure AD login page to get an authorization code
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": "openid profile email User.Read",  # Add the required scopes
    }
    authorization_url_with_params = f"{authorization_url}?{urllib.parse.urlencode(params)}"
    return redirect(authorization_url_with_params)


@app.route("/logout")
def logout():
    session.clear()  # Clear the user's session
    return render_template("index.html")


@app.route("/callback")
def callback():
    # Step 2: Extract the authorization code from the query parameters of the redirected URL.
    authorization_code = request.args.get("code")

    token_data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": authorization_code,
        "redirect_uri": redirect_uri,
        "client_secret": client_secret,
    }

    token_response = requests.post(token_url, data=token_data)

    #Parse the token response to get the access token and its expiration time
    token_info = token_response.json()
    print(token_info)
    id_token = token_info.get("id_token")
    expiration_time = int(token_info.get("expires_in"))
    json_data = validate_jwt(id_token, valid_audiences, issuer)

    email_id = json_data['unique_name']
    id_arr = email_id.split('@')
    cds_id = id_arr[0]

    session['id_token'] = id_token
    session['email_id'] = email_id
    session['cds_id'] = cds_id
    session['token_expiration'] = time.time() + expiration_time

    return redirect(url_for('home'))


if __name__ == "__main__":
    app.run(host='localhost', port=80, debug=True)
