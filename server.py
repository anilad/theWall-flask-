from flask import Flask, request, redirect, render_template, session, flash
from mysqlconnection import MySQLConnector
import re, md5, os, binascii

app = Flask(__name__)
app.secret_key = 'keepitsecretkeepitsafe'
mysql = MySQLConnector(app,'walldb')
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
NAME_REGEX = re.compile(r'^[a-zA-Z]+$')
PASSWORD_REGEX = re.compile(r"^.*(?=.{8,})(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=]).*$")

@app.route('/')
def index():
    if not 'id' in session:
        session['id'] = None
    if not 'name' in session:
        session['name'] = None
    query = "SELECT * FROM users"
    users = mysql.query_db(query) 
    # CHECK IF USER IS CURRENTLY LOGGED IN AND REDIRECT TO THE WALL WITHOUT SIGNING IN
    return render_template('index.html', users=users)

@app.route('/register')
def register():
    return render_template('registration.html')

@app.route('/wall')
def wall():
    query = "SELECT first_name, last_name, messages.message, messages.id, DATE_FORMAT(messages.created_at, '%M %D %Y') AS created_at FROM users JOIN messages ON messages.user_id = users.id"
    join = mysql.query_db(query) 

    commentQuery ="SELECT first_name, last_name, comments.comment, DATE_FORMAT(comments.created_at, '%M %D %Y') AS created_at, comments.message_id, messages.id as msg_id  FROM users JOIN comments ON comments.user_id = users.id JOIN messages ON messages.id = comments.message_id"
    commentJoin = mysql.query_db(commentQuery)
    print join
    print commentJoin

    return render_template('wall.html', messages=join, comments = commentJoin)
    

@app.route('/login', methods=['POST'])
def login():
    eMail = request.form['email']
    if EMAIL_REGEX.match(eMail):
        query = "SELECT first_name, id, email, password, salt FROM users WHERE email = :email"
        data = {
            'email': eMail
        }
        users = mysql.query_db(query,data)
        validPassword = False

        if not users:
            flash('There are no users with this email, please enter a valid email')
            return redirect('/')
        else:
            
            if users[0]['password'] == md5.new(request.form['password'] + users[0]['salt']).hexdigest():
                validPassword=True
            
            if validPassword == True:
                session['id'] = users[0]['id']
                session['name'] = users[0]['first_name']
                # print session['id']
                # print session['first_name']
                return redirect('/wall')
    flash('Incorrect email or password')
    return redirect('/')

@app.route('/process', methods=['POST'])
def process():
    error=False
    fName = request.form['fName']
    lName = request.form['lName']
    eMail = request.form['email']
    password = request.form['password']
    confirm = request.form['confirm']

    query = "SELECT email, password, salt FROM users WHERE email = :email"
    data = {
        'email': eMail
    }
    users = mysql.query_db(query,data)
    print users
    if users==[]:
        if fName=="" or lName =="" or eMail =="" or password =="":
            flash('All fields are required')
            error = True
        else:
            if fName != "":
                if not NAME_REGEX.match(fName):
                    flash("Invalid Name! Name cannot include numbers or special characters.")
                    error=True
            if lName != "":
                if not NAME_REGEX.match(request.form['lName']):
                    flash("Invalid Name! Name cannot include numbers or special characters.")
                    error=True
            if eMail != "":
                if not EMAIL_REGEX.match(eMail):
                    flash("Invalid Email Address!")
                    error = True
            if password != "":
                if not PASSWORD_REGEX.match(password):
                    flash('Password invalid! Password needs at least 8 characters, 1 uppercase, 1 number, 1     special character')
                    error=True
            if confirm != "":
                if confirm != password:
                    flash('Password confirmation does not match Password!')
                    error=True
                else:
                    password = request.form['password']
                    salt =  binascii.b2a_hex(os.urandom(15))
                    hashPass = md5.new(password + salt).hexdigest()
        if error:
            flash('Unable to register')
            return redirect('/register')       
        else: 
            insert_query = "INSERT INTO users (first_name, last_name, email, password, salt, created_at,    updated_at) VALUES (:first_name, :last_name, :email, :password, :salt, NOW(), NOW())"

            query_data = { 'first_name': fName, 'last_name': lName, 'email': eMail, 'password': hashPass,   'salt': salt}

            session['id']= mysql.query_db(insert_query, query_data)
            session['name'] = fName
            print session['id']
            print session['name']
            return redirect('/wall')
    else:
        flash('Unable to register')
        return redirect('/register')
    
@app.route('/message', methods=['POST'])
def messages():
    message=request.form['message']
    if len(message) > 0:
        query = "INSERT INTO messages(message, created_at, updated_at, user_id) VALUES(:message, NOW(), NOW(), :user_id)"
        data = {
            'message': message,
            'user_id': session['id']
        }
        messages = mysql.query_db(query,data)
    print messages
    return redirect('/wall')

@app.route('/comment', methods=['POST'])
def comments():
    query = "INSERT INTO comments(comment, user_id, message_id, created_at, updated_at) VALUES(:comment, :user_id, :message_id, NOW(), NOW())"
    data = {
        'comment': request.form['comment'],
        'user_id': session['id'],
        'message_id': request.form['msgId']
    }
    comments = mysql.query_db(query,data)
    print comments
    return redirect('/wall')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

app.run(debug=True)