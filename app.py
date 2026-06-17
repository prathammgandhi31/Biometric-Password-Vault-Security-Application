import io

from flask import Flask,render_template,url_for,request,send_from_directory,redirect,session
from datetime import timedelta
import sqlite3
import cv2
import dlib
import face_recognition
import numpy
import os
import hashlib
import base64
import qrcode
import pickle
import json
import webbrowser
import pyotp
import bcrypt
import secrets
import string
import math
from flask_assets import Environment, Bundle
#from scipy import io
InternalFilePath = os.curdir + os.sep + "_Internal"
if not os.path.exists(InternalFilePath):
    os.makedirs(os.curdir + os.sep + "Images", exist_ok=True)
else:
    os.makedirs(InternalFilePath + os.sep + "Images", exist_ok=True)
os.makedirs(os.curdir + os.sep + "Temp", exist_ok=True)


app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
assets = Environment(app)

tailwind = Bundle("css/tailwind.css", filters="postcss", output="css/output.css")
assets.register("tailwind", tailwind)

app.permanent_session_lifetime = timedelta(minutes=30)

@app.route("/Images/<filename>")
def get_image(filename):
    return send_from_directory(os.curdir + os.sep + "Images",filename)

@app.route("/adder", methods=['POST','GET'])
def adder():
    if request.method == 'POST':
        SqDB = sqlite3.connect("Suspects.db")
        SQLCURSOR = SqDB.cursor()
        ImageofSuspect = request.files['picture']
        DataStream = ImageofSuspect.stream
        hash_obj = hashlib.md5()
        DataStream.seek(0)
        while chunk := DataStream.read(2048):
            hash_obj.update(chunk)
        ImageFileName = hash_obj.hexdigest()
        if not os.path.exists(InternalFilePath):
            FilePath = os.curdir + os.sep + "Images" + os.sep + ImageFileName + '.' + ImageofSuspect.filename.split('.')[1]
        else:
            FilePath = os.curdir + os.sep + "_Internal" + os.sep + "Images" + os.sep + ImageFileName + '.' + ImageofSuspect.filename.split('.')[1]
        DataStream.seek(0)
        with open(FilePath,"wb") as file:
            while chunk := DataStream.read(2048):
                file.write(chunk)
            file.close()
        SQLCURSOR.execute('SELECT MAX(id) FROM suspects')
        TMPVAL = SQLCURSOR.fetchone()[0]
        if TMPVAL == None:
            NUMofROWS = 1
        else:
            NUMofROWS = TMPVAL + 1
        LoadedFace = face_recognition.load_image_file(FilePath)
        FaceEncoding = face_recognition.face_encodings(LoadedFace)
        if len(FaceEncoding) == 1:
            secret = pyotp.random_base32()
            totp = pyotp.TOTP(secret)
            uri = totp.provisioning_uri(name=request.form['name'], issuer_name="FaceRecogSystem")
            # Generate QR
            qr_img = qrcode.make(uri)
            buf = io.BytesIO()
            qr_img.save(buf, format="PNG")
            qr_base64 = base64.b64encode(buf.getvalue()).decode()
            hashed_password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
            SQLCURSOR.execute("""INSERT INTO suspects VALUES (?,?,?,?,?,?,?) """,(NUMofROWS,request.form['name'],request.form['gender'],hashed_password,secret,ImageFileName + '.' + ImageofSuspect.filename.split('.')[1],pickle.dumps(FaceEncoding[0])))
            SQLCURSOR.close()
            SqDB.commit()
            SqDB.close()
            return render_template("adder.html",Added=True,qr_img=qr_base64,secret=secret)
        else:
            return render_template("adder.html",Added=False)
        
    else:
        return render_template("adder.html")
    
@app.route("/", methods=['POST','GET'])
def index():
    SqDB = sqlite3.connect("Suspects.db")
    SQLCURSOR = SqDB.cursor()
    SQLCURSOR.execute("SELECT COUNT(id) FROM suspects")
    nums = SQLCURSOR.fetchone()
    SQLCURSOR.close()
    return render_template("index.html",NumSus=nums)

@app.route("/viewer", methods=['POST','GET'])
def viewer():
    SqDB = sqlite3.connect("Suspects.db")
    SQLCURSOR = SqDB.cursor()
    SQLCURSOR.execute('SELECT * FROM suspects')
    Data = SQLCURSOR.fetchall()
    SQLCURSOR.close()
    SqDB.close()
    return render_template("viewer.html",Suspects=Data)

@app.route("/delete/<int:id>", methods=['POST','GET'])
def delete(id):
    SqDB = sqlite3.connect("Suspects.db")
    SQLCURSOR = SqDB.cursor()
    SQLCURSOR.execute('SELECT image_path FROM suspects WHERE Id=' + str(id)) #THIS IS VLUNERABLE TO SQL INJECTION PATCH IF NOT USING LOCALLY 
    ImagePath = SQLCURSOR.fetchall()[0]
    if not os.path.exists(InternalFilePath):
        FilePath = os.curdir + os.sep + "Images" + os.sep + ImagePath[0]
    else:
        FilePath = os.curdir + os.sep + "_Internal" + os.sep + "Images" + os.sep + ImagePath[0]
    if os.path.exists(FilePath):
        os.remove(FilePath)
    SQLCURSOR.execute('DELETE FROM suspects WHERE Id=' + str(id)) #THIS IS VLUNERABLE TO SQL INJECTION PATCH IF NOT USING LOCALLY 
    SQLCURSOR.close()
    SqDB.commit()
    SqDB.close()
    return redirect("/viewer")


@app.route("/check", methods=['POST','GET'])
def check():
    if request.method == 'POST':
        SqDB = sqlite3.connect("Suspects.db")
        SQLCURSOR = SqDB.cursor()
        MatchFound = False
        data = request.get_json()
        image_data = data.get("imageData")
        # Decode Base64 image
        image_data = image_data.replace("data:image/png;base64,", "")
        image_bytes = base64.b64decode(image_data)
        PotentialSuspectFilePath = os.curdir + os.sep + 'Temp' + os.sep + 'Potential' + "." + "png"
        with open(PotentialSuspectFilePath, "wb") as f:
            f.write(image_bytes)
        PotentialSuspectNumpyIMG = face_recognition.load_image_file(PotentialSuspectFilePath)
        PotentialSuspectFaceEncodeArray = face_recognition.face_encodings(PotentialSuspectNumpyIMG)
        if len(PotentialSuspectFaceEncodeArray) == 0:
            return json.dumps(False)
        SQLCURSOR.execute("SELECT id,faceencode FROM suspects")
        AllSuspects = SQLCURSOR.fetchall()
        
        Suspect_Encoding = list()
        Suspect_id = list()
        for Suspect in AllSuspects:
            Suspect_id.insert(len(Suspect_id),Suspect[0])
            Suspect_Encoding.insert(len(Suspect_id),pickle.loads(Suspect[1]))
        for PotentialSuspectFaceEncode in PotentialSuspectFaceEncodeArray:
            FaceResult = face_recognition.compare_faces(Suspect_Encoding,PotentialSuspectFaceEncode)
            ValidSuspects = list()
            for Index,Result in enumerate(FaceResult):
                if Result == True:
                    ValidSuspects.insert(len(ValidSuspects),Suspect_id[Index])
            if len(ValidSuspects) == 1:
                SQLCURSOR.execute('SELECT * FROM suspects WHERE id=' + str(ValidSuspects[0]))
                ValidSuspectResults = SQLCURSOR.fetchall()[0]
                MatchFound = True
            if os.path.exists(PotentialSuspectFilePath):
                os.remove(PotentialSuspectFilePath)
            if MatchFound:
                ValidSuspectResults = list(ValidSuspectResults)
                if not bcrypt.checkpw(data.get("password").encode('utf-8'), ValidSuspectResults[3]):
                    # This section checks if the password provided by the user matches the password stored in the database for the matched suspect, this is a basic form of two factor authentication
                    SQLCURSOR.close()
                    SqDB.close() 
                    return json.dumps(False)
                if not pyotp.TOTP(ValidSuspectResults[4]).verify(data.get("twoFA"),valid_window=1):
                    # This section checks if the 2FA code provided by the user matches the 2FA secret stored in the database for the matched suspect, this is a basic form of two factor authentication, it allows for a 1 step window to account for time differences between the server and client
                    SQLCURSOR.close()
                    SqDB.close() 
                    return json.dumps(False)
                SQLCURSOR.close()
                SqDB.close() 
                session["user_id"] = ValidSuspectResults[0]
                session["authenticated"] = True

                # Convert the tuple to a list so we can modify the binary elements safely
                serializable_results = list(ValidSuspectResults[:-1])
                
                # Check if the password hash element (index 3) is a bytes object, and decode it to text
                if isinstance(serializable_results[3], bytes):
                    serializable_results[3] = serializable_results[3].decode('utf-8')

                return json.dumps(serializable_results)

                return json.dumps(serializable_results)
            # If there are multiple valid suspects it will return false to avoid confusion, this can be changed to return all valid users if needed but it would require changes to the frontend as well
        SQLCURSOR.close()
        SqDB.close()
        #THIS IS A MAJOR SECURITY FLAW, ANYONE CAN SEND A POST REQUEST TO THIS ENDPOINT WITH A BASE64 ENCODED IMAGE AND IT WILL CHECK IF THE FACE IN THE IMAGE MATCHES ANY OF THE SUSPECTS IN THE DATABASE, THIS SHOULD BE PATCHED IF NOT USING LOCALLY
        return json.dumps(False)
    else:
        return render_template("check.html")
    

######## Added by P

@app.route("/vault/generate_password", methods=['GET'])
def gen_password():
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for i in range(16))
    return json.dumps({"password":password})

#password auditing
def calculate_entropy(password):
    if not password: return 0

    pool = 0
    if any(c.islower() for c in password): pool+=26
    if any(c.isupper() for c in password): pool+=26
    if any(c.isdigit() for c in password): pool +=10
    if any(c in "!@#$%^&*()-_+=[]{}|;:,.<>?/" for c in password): pool+=32

    if pool == 0: return 0
    #Shannon Entropy calculation
    return len(password) * math.log2(pool)

@app.route("/vault/audit_page")
def audit_page():
    if session.get("authenticated") != True:
        return redirect("/check")
    return render_template("audit.html")

@app.route("/vault/audit", methods=['POST'])
def audit_vault():
    data = request.get_json()
    if session.get("authenticated") != True:
        return json.dumps({"status":"error", "message":" verification failed"})

    db = sqlite3.connect("Suspects.db")
    cursor = db.cursor()
    cursor.execute("SELECT service_name, password FROM vault WHERE user_id=?", (session.get("user_id"),))
    rows = cursor.fetchall()

    report = []
    for service, pwd in rows:
            bits = calculate_entropy(pwd)
            if bits < 40: strength = "Vulnerable"
            elif bits < 60: strength = "Weak"
            elif bits < 80: strength = "Good"
            else: strength = "Excellent"

            report.append({
                "service": service,
                "bits": round(bits, 1),
                "strength": strength
            })

    db.close()
    return json.dumps({"status": "success", "report": report})
    

@app.route("/vault/view", methods=['POST'])
def view_vault(): #View Passwords
    data = request.get_json()
    if session.get("authenticated") != True:
        return json.dumps({"status":"error","message":"Not Authenticated"})

    db = sqlite3.connect("Suspects.db")
    cursor = db.cursor()
    cursor.execute("SELECT id, service_name, username, password FROM vault WHERE user_id=?", (session.get("user_id"),))
    passwords = cursor.fetchall()
    return json.dumps({"status": "success", "data":passwords})
    

@app.route("/vault/add", methods=['POST'])
def add_to_vault():
    if session.get("authenticated") != True:
        return json.dumps({"status":"error","message":"Not Authenticated"})
    data = request.get_json()

    if session.get("authenticated") == True:
        db = sqlite3.connect("Suspects.db")
        cursor = db.cursor()
        cursor.execute("INSERT INTO vault (user_id, service_name, username, password) VALUES (?,?,?,?)", (session.get("user_id"), data['service'], data['user'], data['pwd']))
        db.commit()
        db.close()
        return json.dumps({"status":"success"})
    
    return json.dumps({"status":"error"})

@app.route("/vault")
def vault_page():
    if session.get("authenticated") != True:
        return redirect("/check")
    SqDB = sqlite3.connect("Suspects.db")
    SQLCURSOR = SqDB.cursor()
    SQLCURSOR.execute("SELECT name FROM suspects WHERE id=?", (session.get("user_id"),))
    name = SQLCURSOR.fetchone()[0]
    SQLCURSOR.close()
    SqDB.close() 
    return render_template("vault.html",name=name)

@app.route("/vault/signout")
def signout():
    session.clear()
    return redirect("/check")

##
@app.route("/vault/add_page")
def add_page():
    if session.get("authenticated") != True:
        return redirect("/check")
    return render_template("add_password.html")

@app.route("/vault/view_page")
def view_page():
    if session.get("authenticated") != True:
        return redirect("/check")
    return render_template("view_passwords.html")

@app.route("/vault/delete_page")
def delete_page():
    if session.get("authenticated") != True:
        return redirect("/check")
    return render_template("delete_password.html")

@app.route("/vault/delete", methods=['POST'])
def delete_from_vault():
    if session.get("authenticated") != True:
        return json.dumps({"status":"error","message":"Not Authenticated"})
    data = request.get_json()
    db = sqlite3.connect("Suspects.db")
    cursor = db.cursor()
    cursor.execute("DELETE FROM vault WHERE id=? AND user_id=?", (data['passwordId'], session.get("user_id")))
    db.commit()
    db.close()
    return json.dumps({"status": "success"})


if __name__ == "__main__":
    print("CUDA ENABLED:" +  str(dlib.DLIB_USE_CUDA))
    webbrowser.open_new_tab("http://localhost:5001")
    SqDB = sqlite3.connect("Suspects.db")
    cu = SqDB.cursor()
    cu.execute('''CREATE TABLE IF NOT EXISTS suspects (
    id INTEGER PRIMARY KEY,
    name TEXT,
    gender TEXT, 
    Password TEXT,
    secret TEXT,
    image_path TEXT,
    faceencode BLOB
    )'''
    )
    ####### Added by P
    cu.execute('''CREATE TABLE IF NOT EXISTS vault (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    service_name TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    FOREIGN KEY(user_id) REFERENCES suspects(id)
    )''')
    #######
    cu.close()
    SqDB.commit()
    SqDB = sqlite3.connect("Suspects.db")
    cu = SqDB.cursor()
    cu.execute("VACUUM")
    cu.close()
    SqDB.commit()
    app.run(debug=True, port=5001)
