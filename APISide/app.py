#----------------------------------API & AUTHORIZER SIDE--------------------------
from flask import Flask
from flask import jsonify
from flask import Flask, render_template, redirect, request, session, url_for
import requests
import secrets
import json



#define app
app = Flask(__name__)



#Secret key for sessions
app.secret_key = "ORGSECRETKEY"
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_PERMANENT"] = True


#tokens mock
tokens_mock = []


#Users DB Mock for test
users_mock = [
	{
		"id": "00ub0oNGTSWTBKOLGLNR",
		"status": "ACTIVE",
		"created": "2013-06-24T16:39:18.000Z",
		"activated": "2013-06-24T16:39:19.000Z",
		"statusChanged": "2013-06-24T16:39:19.000Z",
		"lastLogin": "2013-06-24T17:39:19.000Z",
		"lastUpdated": "2013-07-02T21:36:25.344Z",
		"passwordChanged": "2013-07-02T21:36:25.344Z",

		"profile": {
			"firstName": "Isaac",
			"lastName": "Brock",
			"email": "isaac.brock@example.com",
			"login": "isaac.brock@example.com",
			"mobilePhone": "555-415-1337"
		},
		#mock credential
		"password": "mypassword1234"
		# "credentials": {
		# 	"password": {},
		# 	"provider": {
		# 		"type": "IMPORT",
		# 		"name": "IMPORT"
		# 	}
		# },
	}
]


# Global session policy Rules action data > Signon Action > session
pol_db = [
	{
		"id": "nn2aFsasSod21nlc",
		"session": {
        	"usePersistentCookie": False,
        	"maxSessionIdleMinutes": 1,
        	"maxSessionLifetimeMinutes": 0
      	}
	}
]




#----------------------------------------AUTHORIZER-----------------------------------

#Authorize before login callback
@app.route("/mock-oauth2/default/v1/authorize")
def authorize():

	#get parameters
	state = request.args.get("state")
	redirect_to = request.args.get("redirect_to")
	
	#check if app state and redirect_to parameters
	if not state or not redirect:

		return "Malformed request"


	#store login status
	session["authorize_state"] = state


	return render_template("login.html", state=state, redirect_to=redirect_to)





#Authorize before login callback
@app.route("/mock-oauth2/default/v1/authorize/login", methods=["POST"])
def login():

	#check request method
	if request.method == "GET":

		return "Invalid request method"

	#get username and password
	username = request.form.get("username")
	password = request.form.get("pass")

	#get state and redirect to
	state = request.form.get("state")
	redirect_to = request.form.get("redirect_to")

	#check if credentials exists
	if not username or not password:

		return "No provided credentials"

	#check state and redirect to
	if not state or not redirect_to:

		return "Missing app state"

	#check state integrity
	if session["authorize_state"] != state:

		return "Invalid app state"


	#check credentials
	get_user =  next((user for user in users_mock if user["profile"]["email"] == username), False)

	#if user
	if not get_user:

		return "No found user"

	#check if wrong credentials
	if get_user["password"] != password:
		
		return "Wrong credentials"

	#user session token
	user_token = secrets.token_urlsafe(64)

	#callback state
	callback_state = {
		"user_token": user_token,
		"state": state,
	}


	#user_info
	user_info = {
		"user_token": user_token,
		"user_info": get_user

	}

	tokens_mock.append(user_info)


	#callback uri
	callback = "{base_url}?{query_params}".format(
		base_url=redirect_to,
		query_params=requests.compat.urlencode(callback_state)
	)

	return redirect(callback)




@app.route("/mock-oauth2/default/v1/userinfo")
def userinfo():

	#provided token
	headers = request.headers
	bearer = headers.get("Authorization")
	token = bearer.split()[1]

	#get user by token
	get_user_by_token =  next((user["user_info"] for user in tokens_mock if user["user_token"] == token), False)

	if not get_user_by_token:

		return "No user found"

	return  jsonify(get_user_by_token)






#------------------------------------API-----------------------------------------------



@app.route("/mock-api/v1/policies/<policy_id>")
def get_policy(policy_id):

	#provided token
	headers = request.headers
	bearer = headers.get("Authorization")
	provided_token = bearer.split()[1]

	#get user by token
	get_user_by_token =  next((token for token in tokens_mock if token["user_token"] == provided_token), False)

	#check token
	if not get_user_by_token:

		return "Invalid token"

	#get user by token
	get_policy =  next((pol for pol in pol_db  if pol["id"] == policy_id), False)

	print("POL",get_policy)

	#check policy
	if not get_policy:

		return "Policy not found"


	return  jsonify(get_policy)




	

@app.route("/")
def root():
	
	return "API & Authorizer Side"