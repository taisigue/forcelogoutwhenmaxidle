#----------------------------------APP SIDE--------------------------
#imports
from flask import Flask
from user import User
from flask import Flask, render_template, redirect, request, session, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
import secrets
import requests
from datetime import datetime

app = Flask(__name__, template_folder="templates")



#datetime format
FTM = "%Y-%m-%d %H:%M:%S.%f"


#BASE_URL'S
API_AUTHORIZE_URL = "http://localhost:4040"

#APPLICATION GLOBAL SESSION POLICY ID () -> we need the rules -> signon action -> maxSessionIdleTime
GS_POLICY_ID = "nn2aFsasSod21nlc"

#Secret key for session
app.secret_key = "ORGSECRETKEY"
app.config["SESSION_TYPE"] = "filesystem"

#login manager
login_manager = LoginManager()
login_manager.init_app(app)



#------------------------------------IDLE FORCE LOGOUT
@login_required
def reachMaxIdle():

    print("\n[CHECK IDLE TIME]")

    #max idle time
    max_idle_time = session["session_timestamps"]["maxSessionIdleMinutes"]

    #last activity
    last_activity = session["session_timestamps"]["lastActivity"]
    last_activity = datetime.strptime(last_activity, FTM)

    #now
    now_str = datetime.utcnow().strftime(FTM)
    now = datetime.strptime(now_str, FTM)

    #delta
    delta = now - last_activity
    delta_mins = delta.seconds / 60

    print("max:",max_idle_time)
    print("delta-mins:",delta_mins)

    #check idle
    if delta_mins >= max_idle_time:
        print("Logout")
        return True
    else:
        print("Reset")
        session["session_timestamps"]["lastActivity"] = now_str

        return False





#---------------------------------------AUTH-----------------------------------------------


#login manager
@login_manager.user_loader
def load_user(user_id):

    return User.get(user_id)



#login
@app.route("/login")
def login():

    #app state
    session["state"] = secrets.token_urlsafe(64)

    query_params = {
        "state": session["state"],
        "redirect_to": "http://localhost:5000/mock-authorization-code/callback"
    }

    # build request_uri
    request_uri = "{base_url}?{query_params}".format(
        base_url=API_AUTHORIZE_URL+ "/mock-oauth2/default/v1/authorize",
        query_params=requests.compat.urlencode(query_params)
    )

    
    return redirect(request_uri)




#callback
@app.route("/mock-authorization-code/callback")
def callback():

    #get args
    user_token = request.args.get("user_token")
    state = request.args.get("state")
  
    #check user token
    if not user_token:

        return "No retrieved user token"

    #if missing state
    if not state :

        return "Missing state"


    #if state not equal to retrieved state
    if state != session["state"]:

        return "Invalidad state"

    #get user
    userinfo_response = requests.get("http://localhost:4040" + "/mock-oauth2/default/v1/userinfo",
                                    headers={'Authorization': f'Bearer {user_token}'}).json()

    #/api/v1/policies/${policyId}
    gs_policy_response = requests.get("http://localhost:4040" + f"/mock-api/v1/policies/{GS_POLICY_ID}",
                                    headers={'Authorization': f'Bearer {user_token}'}).json()




    #store user
    unique_id = userinfo_response["id"]
    user_email = userinfo_response["profile"]["email"]
    user_name = userinfo_response["profile"]["firstName"]



    #create user
    user = User(
        id_=unique_id, name=user_name, email=user_email
    )

    #create in mock session db
    if not User.get(unique_id):

        User.create(unique_id, user_name, user_email)

    #set user as login
    login_user(user)


    #DATETIME ISO8601
    #create timestamp
    session["session_timestamps"] = {
        "lastActivity": datetime.utcnow().strftime(FTM),
        "maxSessionIdleMinutes": gs_policy_response["session"]["maxSessionIdleMinutes"]
    }


    return redirect(url_for("profile"))




#logout call
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    logout_user()

    return redirect(url_for("home"))



#-------------------------------------------AUTH-------------------------------------------


#--------------------------------------------NAV--------------------------------------

#home
@app.route("/")
def home():

    return render_template("home.html")


#profile
@app.route("/profile",  methods=['GET', 'POST'])
@login_required
def profile():

    #check session idle
    if reachMaxIdle():

        return redirect(url_for("logout"))

    return render_template("profile.html", user=current_user)


#contact
@app.route("/our",  methods=['GET', 'POST'])
@login_required
def our():

    #check session idle
    if reachMaxIdle():

        return redirect(url_for("logout"))

    return render_template("our.html")


#aboutus
@app.route("/aboutus",  methods=['GET', 'POST'])
@login_required
def aboutus():

    #check session idle
    if reachMaxIdle():

        return redirect(url_for("logout"))

    return render_template("aboutus.html")


#-------------------------------------------NAV--------------------------------------------------





#main
if __name__ == '__main__':

    app.run(host="localhost", port=5000, debug=True)


