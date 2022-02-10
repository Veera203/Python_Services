import re
from flask import Flask,  request
import logging
import socket
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)

app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'sql@123'
app.config['MYSQL_DB'] = 'org_info'

mysql = MySQL(app)


root_logger = logging.getLogger()
root_logger.setLevel(logging.WARNING)
handler = logging.FileHandler('example.log', 'w')
handler.setFormatter(logging.Formatter('%(asc_time)s - %(name)s - %(level_name)s - %(message)s'))
logging.basicConfig(format='%(asc_time)s - %(message)s', level=logging.INFO)
root_logger.addHandler(handler)


@app.route('/users/create', methods=['POST'])
def register():
    if 'username' in request.json and 'password' in request.json \
       and 'email' in request.json and 'phone' in request.json and 'ip' in request.json and 'date' in request.json:
        username = request.json['username']
        email = request.json['email']
        phone = request.json['phone']
        password = request.json['password']
        hashed_password = generate_password_hash(password)
        user_ip = request.json['ip']
        date = request.json['date']
        device = socket.gethostname()
        print(device)

        # Cursor:-
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM user_signup WHERE USER_MAIL_ID = %s OR USER_PHONE_NUMBER = %s', (email, phone))
        account = cursor.fetchone()

        if account and account[2] == email:
            msg = 'Your mailid already exisit please enter new mailid  !!!!'

        elif account and account[3] == phone:
            msg = "Your phone number is duplicate please enter new number!!!"

        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = ' mail id must contain @ domain name !'

        elif not re.match(r'[A-Za-z]+', username):
            msg = 'Username must contain only characters !'

        elif not re.match(r'^[A-Za-z0-9@#$%^&+=]{8,32}', password):
            msg = 'Password must contain alpha_number with special_characters !'

        elif not re.match(r'^(?:(?:\+|0{0,2})91(\s*[\-]\s*)?|[0]?)?[789]\d{9}$', phone):
            msg = ' phone number must contain ten digits, must starts with 9 or 8 or 7 and starts with +91 !'

        elif not re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                          user_ip):
            msg = 'Invalid ip address format !'

        elif not re.match(r'^(19|20)\d\d[- /.](0[1-9]|1[012])[- /.](0[1-9]|[12][0-9]|3[01])$', date):
            msg = ' date format start with year, month and date !'

        elif not username or not password or not email or not phone or not user_ip or not date:
            msg = 'Please fill out the form !'

        else:
            cur = mysql.connection.cursor()
            cur.execute(
                "insert into user_signup(USER_NAME,USER_MAIL_ID,USER_PHONE_NUMBER,USER_PASSWORD,USER_IP,"
                "USER_DATE_CREATED,USER_DEVICE) VALUES(%s,%s,%s,%s,%s,%s,%s)",
                (username, email, phone, hashed_password, user_ip, date, device))
            mysql.connection.commit()
            # details = cur.fetchall()
            logging.info("successfully registered")
            return "successfully inserted", 200
        return msg
    return "invalid parameters"


@app.route('/login', methods=["POST"])
def login():
    if 'email' in request.json and 'password' in request.json:
        email = request.json["email"]
        logging.info('Admin logged in')
        pw = request.json["password"]
        logging.warning('Watch out!')
        cur = mysql.connection.cursor()
        cur.execute("select * from user_signup WHERE (USER_MAIL_ID = %s )", (email,))
        details = cur.fetchone()
        if details is None:
            return ({"message": "No details"}), 401
        hashed_password = details[4]
        password_match = check_password_hash(hashed_password, pw)
        if password_match:
            return "successfully login"
        else:
           logging.error("Invalid credentials")

        return ({"Error": "invalid credentials"}), 401

    return "Insufficient parameters", 400


if __name__ == "__main__":
    app.run()
