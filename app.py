#app.py
import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request, render_template
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

app = Flask("theinsightco")  #naming our application
app.secret_key = "theinsightco"  #it is necessary to set a password when dealing with OAuth 2.0
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  #this is to set our environment to https because OAuth 2.0 only supports https environments

GOOGLE_CLIENT_ID = "274941190892-g239vi85qo5uvdsk848h60qs3up6udsa.apps.googleusercontent.com"  #enter your client id you got from Google console
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")  #set the path to where the .json file you got Google console is

flow = Flow.from_client_secrets_file(  #Flow is OAuth 2.0 a class that stores all the information on how we want to authorize our users
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  #here we are specifing what do we get after the authorization
    redirect_uri="https://theinsightco.herokuapp.com/callback"  #and the redirect URI is the point where the user will end up after the authorization
)

def login_is_required(function):  #a function to check if the user is authorized or not
    def wrapper(*args, **kwargs):
        if "google_id" in session or "user_id" in session: 
            #authorization required
            return function()
        else:
            return abort(401)

    return wrapper

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if username == "TheInsightCo" and password == "theinsightco":
        session["user_id"] = "12345678"
        session["name"] = username
        return redirect("/home")
    else:
        return render_template('index.html', errorMsg = "Please provide valid username and password")

@app.route("/google/login")  #the page where the user can login
def google_login():
    authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")  #this is the page that will handle the callback process meaning process after the authorization
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  #state does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID,
        clock_skew_in_seconds=1
    )

    session["google_id"] = id_info.get("sub")  #defing the results to show on the page
    session["name"] = id_info.get("name")
    return redirect("/home")  #the final page where the authorized users will end up


@app.route("/logout")  #the logout page and function
def logout():
    session.clear()
    return redirect("/")


@app.route("/")  #the home page where the login button will be located
def index():
    return render_template('index.html')

@app.route("/sourcewisejobs")
def sourcewisejobs():
    return render_template('sourcewisejobs.html', username=session['name'])

@app.route("/statewisejobs")
def statewisejobs():
    return render_template('statewisejobs.html', username=session['name'])

@app.route("/citywiselisting")
def citywiselisting():
    return render_template('citywiselisting.html', username=session['name'])

@app.route("/jobpositionslist")
def jobpositionslist():
    return render_template('jobpositionslist.html', username=session['name'])

@app.route("/aspirantscurrentstatus")
def aspirantscurrentstatus():
    return render_template('aspirantscurrentstatus.html', username=session['name'])

@app.route("/developmentarea")
def developmentarea():
    return render_template('developmentarea.html', username=session['name'])

@app.route("/skillsets")
def skillsets():
    return render_template('skillsets.html', username=session['name'])

@app.route("/genderbasedemployees")
def genderbasedemployees():
    return render_template('genderbasedemployees.html', username=session['name'])

@app.route("/averagesalary")
def averagesalary():
    return render_template('averagesalary.html', username=session['name'])

@app.route("/averagerating")
def averagerating():
    return render_template('averagerating.html', username=session['name'])

@app.route("/home")
@login_is_required
def home():
    return render_template('home.html', username=session['name'])

if __name__ == "__main__":  #and the final closing function
    app.run(debug=True)