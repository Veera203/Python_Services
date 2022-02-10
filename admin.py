from flask import request
from flask_mysqldb import MySQL
import MySQLdb.cursors
from flask_restful import Api
import logging
from flask import Flask, jsonify
from models import UserSignUp
import hashlib
import datetime
import jwt
import time
import socket
from functools import wraps

app = Flask(__name__)
api = Api(app)

app.secret_key = 'SECRET KEY'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'CLINICALFIRST'
mysql = MySQL(app)


@app.route('/api/signup', methods=['POST'])
def usersignup(fun):
    @wraps(fun)
    def Wrapperuser_signup(*args, **kwargs):
        if request.method == 'POST' and (request.json or request.form):
            user_signup_obj = None
            print(request.json)
            if request.json:
                user_signup_obj = UserSignUp(request.json)
            elif request.form:
                user_signup_obj = UserSignUp(request.form)
            if not user_signup_obj:
                return "invalid input"

            if not user_signup_obj.validate_password():
                return 'Passwords does not match', 400
            h = hashlib.md5(user_signup_obj.user_password.encode())
            user_ip = get_ip()
            user_device = get_device()
            try:
                user_signup_obj.validate()
            except ValueError as e:
                return jsonify({"message": e.args}), 401
            # return db.insert_user(user_signup_obj, mysql, h, user_ip, user_device) wraps return statement
            try:
                cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute(
                    'INSERT INTO USER_SIGNUP (USER_ID,USER_NAME,USER_MAIL_ID,USER_PHONE_NUMBER,USER_PASSWORD,USER_IP,USER_DEVICE,USER_DATE_CREATED) VALUES (%s, % s, %s, %s,% s, % s, %s, %s)',
                    (get_userid(cursor),
                     user_signup_obj.user_name,
                     user_signup_obj.user_mail_id,
                     user_signup_obj.user_phone_number,
                     h.hexdigest(),
                     user_ip,
                     user_device,
                     time.strftime('%Y-%m-%d %H:%M:%S')))
                mysql.connection.commit()
                cursor.close()
                return fun("User created successfully", *args,**kwargs), 200
            except Exception as e:
                print(e)
                return jsonify({"message": "User already exists."}), 401

    return Wrapperuser_signup


def get_ip():
    hostName = socket.gethostname()
    ipaddr = socket.gethostbyname(hostName)
    return ipaddr


def get_device():
    hostName = socket.gethostname()
    return hostName


def get_userid(cursor):
    try:
        cursor.execute('SELECT SUBSTRING(MAX(USER_ID),3) AS ID from user_signup')
        max_id = cursor.fetchone()
        concatString = ("US" + str("{:03d}".format(int(max_id['ID']) + 1)))
    except:
        string = "US"
        num = "001"
        concatString = string + num
    return concatString


def max_id_value(c):
    max_value_query = "SELECT substring(patient_id,6) as id FROM patient_personal WHERE substring(patient_id," \
                      " 6)=(SELECT MAX(CAST(SUBSTRING(patient_id,6) AS SIGNED)) FROM patient_personal) "
    c.execute(max_value_query)
    result_value = c.fetchone()
    if result_value == 0 or result_value == 'None' or result_value == '' or result_value is None:
        result_value = 1;
        return result_value
    else:
        result_value = int(result_value[0]) + 1
        return result_value

def user_login(log):
    @wraps(log)
    def Wrapperlogin(*args, **kwargs):
        if request.method == 'POST' and (request.json or request.form):
            user_mail_id = None
            user_phone_number = None
            logging.info('Admin logged in')
            user_password = None
            logging.warning('Watch out!')
            if request.json and request.json['user_mail_id'] and request.json['user_password']:
                user_mail_id = request.json['user_mail_id']
                user_password = request.json['user_password']
            elif request.form and request.form.get('user_mail_id') and request.form.get('user_password'):
                user_mail_id = request.form.get('user_mail_id')
                user_password = request.form.get('user_password')
            if not user_mail_id or not user_password:
                print({"Error": "Invalid Input Details"})


            h = hashlib.md5(user_password.encode())
            print(h.hexdigest())
            cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute(
                'SELECT * FROM USER_SIGNUP WHERE USER_MAIL_ID = %s OR USER_PHONE_NUMBER = %s AND USER_PASSWORD = %s',
                (user_mail_id, user_phone_number, h.hexdigest()))
            details = cursor.fetchone()
            if details is None:
                return "Email not registered", 400
            # if account is none:
            #     return log(account,*args,**kwargs)
            if user_password:
                # generate the JWT Token
                data = {
                    'user_mail': user_mail_id,
                    'password': user_password,
                    'role': details[9],
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}
                token = jwt.encode(data, app.config['SECRET_KEY'], algorithm='HS256')
                data['token'] = token
                return log(data, args, *kwargs)
            else:
                logging.error("Invalid credentials")
                return "invalid credentials", 401

        return "Insufficient parameters", 400
    return Wrapperlogin

@app.route('/api/login', methods=['POST'])
@user_login
def logintest(log):
    return log
