from flask import Flask, request, make_response, jsonify, Response
from werkzeug.utils import secure_filename
from flask_restful import Resource, Api 
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy 
from functools import wraps


import jwt 
import os 
from datetime import datetime
from cryptography.fernet import Fernet
# import datetime
import secrets
import json

app = Flask(__name__)
api = Api(app)

CORS(app)

import os
from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename

#send email
import os
from flask import Flask, flash, request, redirect, url_for
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from PIL import Image
import io


filename = os.path.dirname(os.path.abspath(__file__))
database = 'sqlite:///' + os.path.join(filename, 'db360AMS.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = database 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.config['SECRET_KEY'] = "cretivoxtechnology22"
key = b'qXkOeccBROMqPi3MCFrNc6czJDrEJopBOpoWWYBKdpE='
fernet = Fernet(key)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(255))
    
    clientAMS = db.relationship("ClientAMS", back_populates='user')
    
    
class ClientAMS(db.Model):
    id = db.Column(db.Integer, primary_key = True, unique = True)
    username = db.Column(db.Text)
    password = db.Column(db.Text)
    lastlogin = db.Column(db.JSON)
    count = db.Column(db.Integer)
    #InputLink_relation
    
    adsAMS = db.relationship("AdsAMS", back_populates='clientAMS')
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    user = db.relationship('User', back_populates="clientAMS")
    
class AdsAMS(db.Model):
    id = db.Column(db.Integer, primary_key = True, unique = True)
    name = db.Column(db.Text)
    url = db.Column(db.Text)
    duration = db.Column(db.Integer)
    typeads = db.Column(db.Text)

    
    clientAMS_id = db.Column(db.Integer, db.ForeignKey('clientAMS.id'))
    clientAMS = db.relationship('ClientAMS', back_populates="adsAMS")

db.create_all()

def token_api(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = ""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        
        # token = request.args.get('token') 
        if not token:
            return make_response(jsonify({"msg":"there is no token"}), 401)
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return make_response(jsonify({"msg":"invalid token"}), 401)
        return f(*args, **kwargs)
    return decorator

class Userall(Resource):
    def post(self):
        dataUsername = request.form.get('username')
        dataPassword = fernet.encrypt(request.form.get('password').encode())
        existing_user = User.query.filter(User.username == dataUsername).first()
        if existing_user:
            return make_response(jsonify({"msg":"Username already exists"}), 200)
        if dataUsername and dataPassword:
            dataModel = User(username=dataUsername, password=dataPassword)
            db.session.add(dataModel)
            db.session.commit()
            return make_response(jsonify({"msg":"success"}), 200)
        return jsonify({"msg":"Username / password is empty"})
    
    def get(self):
        dataQuery = User.query.all()
        output = [{
            "id" : data.id,
            "username" : data.username
            
        } for data in dataQuery
        ]

        return make_response(jsonify(output), 200)
    
    @token_api
    def delete(self):
        token = ""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, "cretivoxtechnology22", algorithms=['HS256'])
        print(decoded_token["username"])
        if decoded_token["username"] == "admin":
            db.session.query(User).delete()
            db.session.commit()
                
            return jsonify({"msg":"Deleted"}) 
        else:
            return jsonify({"msg" : "Only Admin"})
    
class Userid(Resource):
    def get(self,id):
        data = User.query.filter(User.id == id).first()
        output = [{
            "id" : data.id,
            "data" : {
                "username" : data.username
            }
        }
        ]
        return make_response(jsonify(output), 200)
    
    @token_api
    def put(self,id):
        token = ""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, "cretivoxtechnology22", algorithms=['HS256'])
        print(decoded_token["username"])
        if decoded_token["username"] == "admin":
            dataUsername = request.form.get('username')
            dataPassword = fernet.encrypt(request.form.get('password').encode())
            existing_user = User.query.filter(User.username == dataUsername).first()
            if existing_user:
                return make_response(jsonify({"msg":"Username already exists"}), 200)
            dataUpdate = User.query.filter(User.id == id).first()
            if dataUsername:
                dataUpdate.username = dataUsername
            if dataPassword:
                dataUpdate.password = dataPassword
            db.session.commit()
            return make_response(jsonify({"msg" : "updated"}),200)
        else:
            return jsonify({"msg" : "Only Admin"})
        
    @token_api
    def delete(self,id):
        token = ""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, "cretivoxtechnology22", algorithms=['HS256'])
        print(decoded_token["username"])
        if decoded_token["username"] == "admin":
            own = User.query.filter(User.id == id).first()
            db.session.delete(own)
            db.session.commit()
            return jsonify({"msg":"Deleted"})
        else:
            return jsonify({"msg" : "Only Admin"})
    
class LoginUser(Resource):
    def post(self):
        dataUsername = request.form.get('username')
        dataPassword = request.form.get('password')   
        queryUsername = [data.username for data in User.query.all()]
        queryPassword = [fernet.decrypt(bytes(data.password)).decode()  for data in User.query.all()]

        
        if dataUsername in queryUsername and dataPassword in queryPassword :
            token = jwt.encode(
                {
                    "username":dataUsername
                }, app.config['SECRET_KEY'],  algorithm="HS256"
            )
            
            output = [{
                "token" : token,
                "msg" : "success"
                     
            }
            ]
            return make_response(jsonify(output), 200)
        return jsonify({"msg":"failed"})
    


class ClientAmsall(Resource):
    @token_api
    def post(self):
        token = ""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, "cretivoxtechnology22", algorithms=['HS256'])
        print(decoded_token["username"])
        if decoded_token["username"] == "admin":
            datauser = request.form.get('username')
            dataPassword = fernet.encrypt(request.form.get('password').encode())
            # datacount = request.form.get('count')
            
            existing_user = ClientAMS.query.filter(ClientAMS.username == datauser).first()
            if existing_user:
                return make_response(jsonify({"msg":"Username already exists"}), 200)

            dataModel = ClientAMS(username = datauser, password = dataPassword, count = 0, user_id = 1)
            db.session.add(dataModel)
            db.session.commit()
            return make_response(jsonify({"msg":"success"}), 200)
        else:
            return jsonify({"msg" : "Only Admin"})

    def get(self):
        dataQuery = ClientAMS.query.all()
        output = [{
            "id" : data.id,
            "data" : {
                "username" : data.username,
                "count" : data.count,
                "lastlogin" : json.loads(data.lastlogin) if data.lastlogin else []
                
            }        
        } for data in dataQuery
        ]

        return make_response(jsonify(output), 200)
    
    @token_api
    def delete(self):
        token = ""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, "cretivoxtechnology22", algorithms=['HS256'])
        print(decoded_token["username"])
        if decoded_token["username"] == "admin":
            db.session.query(ClientAMS).delete()
            db.session.commit()
                
            return jsonify({"msg":"Deleted"}) 
        else:
            return jsonify({"msg" : "Only Admin"})

class ClientAmsid(Resource):
    def get(self,id):
        data = ClientAMS.query.filter(ClientAMS.id == id).first()
        output = [{
            "id" : data.id,
            "data" : {
                "username" : data.username,
                "count" : data.count,
                "lastlogin" : json.loads(data.lastlogin) if data.lastlogin else []
            }        
        }
        ]
        return make_response(jsonify(output), 200)
    
    @token_api
    def put(self,id):
        dataUpdate = ClientAMS.query.filter(ClientAMS.id == id).first()
        token = ""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, "cretivoxtechnology22", algorithms=['HS256'])
        # print(decoded_token["username"])
        if decoded_token["username"] == "admin":
            dataUsername = request.form.get('username')
            
            if request.form.get('password') is not None:
                dataPassword = fernet.encrypt(request.form.get('password').encode())
            else:
                dataPassword = fernet.decrypt(dataUpdate.password).decode()
            # print(dataPassword)
            dataCount = request.form.get("count")
            existing_user = ClientAMS.query.filter(ClientAMS.username == dataUsername).first()
            if existing_user:
                return make_response(jsonify({"msg":"Username already exists"}), 200)
            # dataUpdate = ClientAMS.query.filter(ClientAMS.id == id).first()
            
            if dataUsername:
                dataUpdate.username = dataUsername
            if dataPassword:
                dataUpdate.password = dataPassword
            if dataCount:
                count = int(dataUpdate.count) + int(dataCount)
                dataUpdate.count = count
            db.session.commit()
            return make_response(jsonify({"msg" : "updated"}),200)
        else:
            return jsonify({"msg" : "Rejected"})
        
    @token_api
    def delete(self,id):
        token = ""
        auth_header = request.headers.get('Authorization')
        if auth_header:
            token = auth_header.split(" ")[1]
        decoded_token = jwt.decode(token, "cretivoxtechnology22", algorithms=['HS256'])
        print(decoded_token["username"])
        if decoded_token["username"] == "admin":
            own = ClientAMS.query.filter(ClientAMS.id == id).first()
            for x in range (len(own.adsAMS)):
                own.adsAMS[x].clientAMS_id = None
            db.session.delete(own)
            db.session.commit()
            return jsonify({"msg":"Deleted"})
        else:
            return jsonify({"msg" : "Only Admin"})

class LoginClient(Resource):
    def post(self):
        dataUsername = request.form.get('username')
        dataPassword = request.form.get('password')   
        queryUsername = [data.username for data in ClientAMS.query.all()]
        queryPassword = [fernet.decrypt(bytes(data.password)).decode()  for data in ClientAMS.query.all()]
        datadate = datetime.now()
        formatted_datetime = datadate.strftime("%Y-%m-%d %H:%M:%S")
        
        
        dbclient = ClientAMS.query.all()
        queryclient = [data.username for data in ClientAMS.query.all()]
        
        if dataUsername in queryclient:
            for i in range(len(dbclient)):
                if dbclient[i].username == dataUsername:
                    datalogin = json.loads(dbclient[i].lastlogin) if dbclient[i].lastlogin else []
                    datalogin.append(formatted_datetime)
                    dbclient[i].lastlogin = json.dumps(datalogin)
                    id_client = dbclient[i].id
                    db.session.commit()

        
        if dataUsername in queryUsername and dataPassword in queryPassword :
            token = jwt.encode(
                {
                    "username":dataUsername
                }, app.config['SECRET_KEY'],  algorithm="HS256"
            )
            
            output = [{
                "id" : id_client,
                "token" : token,
                "msg" : "success"
                     
            }
            ]
            return make_response(jsonify(output), 200)
        return jsonify({"msg":"failed"})

class AdsAll(Resource):
    @token_api
    def post(self):
        dataname = request.form.get('name')
        dataurl = request.form.get('url')
        dataduration = request.form.get('duration')
        datatype = request.form.get('type')
        dataclient = request.form.get('client')
        existing_user = AdsAMS.query.filter(AdsAMS.name == dataname).first()
        # if existing_user:
        #     return make_response(jsonify({"msg":"Username already exists"}), 200)
        
        dbclient = ClientAMS.query.all()
        queryclient = [data.username for data in ClientAMS.query.all()] 
        print(dataclient)
        if dataclient in queryclient :
            for i in range(len(dbclient)):
                if dbclient[i].username == dataclient:
                    id_client= dbclient[i].id
        
        dataModel = AdsAMS(name = dataname, url = dataurl, duration = dataduration, clientAMS_id = id_client, typeads = datatype)
        db.session.add(dataModel)
        db.session.commit()
        return make_response(jsonify({"msg":"success"}), 200)
        
    def get(self):
        dataquery = AdsAMS.query.all()
        output =[{
            "id" : data.id,
            "data" : {
                "name" : data.name,
                "url" : data.url,
                "duration" : data.duration,
                "type" : data.typeads
            }
        }for data in dataquery]
        return make_response(jsonify(output), 200)
    
    @token_api
    def delete(self):
        db.session.query(AdsAMS).delete()
        db.session.commit()
        return jsonify({"msg" : "Deleted"})
    
class Adsid(Resource):
    def get(self,id):
        data = AdsAMS.query.filter(AdsAMS.id == id).first()
        output = [{
            "id" : data.id,
            "data" : {
                "name" : data.name,
                "duration" : data.duration,
                "url" : data.url,
                "type" : data.typeads
            }        
        }
        ]
        return make_response(jsonify(output), 200)
    
    @token_api
    def put(self,id):
        dataname = request.form.get('name')
        dataurl = request.form.get('url')
        dataduration = request.form.get('duration')
        datatype = request.form.get('type')
        dataclient = request.form.get('client')
        # print(dataname, dataurl, dataduration, datatype, dataclient)
        existing_user = AdsAMS.query.filter(AdsAMS.name== dataname).first()
        if existing_user:
            print("same")
            # return make_response(jsonify({"msg":"ads name already exists"}), 200)
        
        dbclient = ClientAMS.query.all()
        queryclient = [data.username for data in ClientAMS.query.all()]
        if dataclient in queryclient:
            for i in range(len(dbclient)):
                if dbclient[i].username == dataclient:
                    id_client= dbclient[i].id
        
        
        dataUpdate = AdsAMS.query.filter(AdsAMS.id == id).first()
        
        if dataname:
            dataUpdate.name = dataname
            print(dataname)
        if dataurl:
            dataUpdate.url = dataurl
            print(dataurl)
        if dataduration:
            dataUpdate.duration = dataduration
            print(dataduration)
        if datatype:
            dataUpdate.typeads = datatype
            print(datatype)
        if dataclient:
            dataUpdate.clientAMS_id = id_client
            print(dataclient)
        db.session.commit()
        return make_response(jsonify({"msg" : "updated"}),200)
    
    @token_api
    def delete(self,id):
        own = AdsAMS.query.filter(AdsAMS.id == id).first()
        db.session.delete(own)
        db.session.commit()
        return jsonify({"msg":"Deleted"})
    
class ClientRelation(Resource):
    def get(self):
        dataQuery = ClientAMS.query.all()
        output = []
        for i in range(len(dataQuery)):
            print(len(dataQuery[i].adsAMS))
            adsval = []
            for x in range(len(dataQuery[i].adsAMS)):
                listval = {
                    "id" : dataQuery[i].adsAMS[x].id,
                    "url": dataQuery[i].adsAMS[x].url,
                    "duration" : dataQuery[i].adsAMS[x].duration,
                    "type" : dataQuery[i].adsAMS[x].typeads
                }
                adsval.append(listval)
            
            val = {
                "id" : dataQuery[i].id,
                "data" : {
                    "username" : dataQuery[i].username,
                    "count" : dataQuery[i].count,
                    "lastlogin" : json.loads(dataQuery[i].lastlogin) if dataQuery[i].lastlogin else []  
                    } ,
                    "ads" : adsval
            }
            output.append(val)
        return make_response(jsonify(output), 200)
        
    
class ClientRelationid(Resource):
    def get(self,id):
        dataQuery = ClientAMS.query.filter(ClientAMS.id == id).first()
        output, listads = [], []
        print(dataQuery.adsAMS[0].clientAMS_id)
        for x in range(len(dataQuery.adsAMS)):
            listval = {
                "id" : dataQuery.adsAMS[x].id,
                "name" : dataQuery.adsAMS[x].name,
                "url": dataQuery.adsAMS[x].url,
                "duration" : dataQuery.adsAMS[x].duration,
                "type" : dataQuery.adsAMS[x].typeads
            }
            listads.append(listval)
        
        val = {
            "id" : dataQuery.id,
            "data" : {
                "username" : dataQuery.username,
                "count" : dataQuery.count,
                "lastlogin" : json.loads(dataQuery.lastlogin) if dataQuery.lastlogin else [],
                "ads" : listads
            }     
        }
        output.append(val)
        return make_response(jsonify(output), 200) 

class AdsRelationAll(Resource):
    def get(self):
        dataQuery = AdsAMS.query.all()
        # print(dataQuery[0].clientAMS.username)
        output = []
        for i in range(len(dataQuery)):
            if dataQuery[i].clientAMS_id is not None:
                val = {
                    "id" : dataQuery[i].id,
                    "data" : {
                        "name" : dataQuery[i].name,
                        "duration" : dataQuery[i].duration,
                        "url" : dataQuery[i].url,
                        "type" : dataQuery[i].typeads
                    },
                    "client" : dataQuery[i].clientAMS.username
                }
            else:
                val = {
                    "id" : dataQuery[i].id,
                    "data" : {
                        "name" : dataQuery[i].name,
                        "duration" : dataQuery[i].duration,
                        "url" : dataQuery[i].url,
                        "type" : dataQuery[i].typeads
                    },
                    "client" : None
                }
            output.append(val)
        return make_response(jsonify(output),200)

class AdsRelationid(Resource):
    def get(self,id):
        dataQuery = AdsAMS.query.filter(AdsAMS.id == id).first()
        # print(dataQuery.clientAMS.username) 
        if dataQuery.clientAMS_id is not None:   
            output = [{
                "id" : dataQuery.id,
                "data" : {
                    "name" : dataQuery.name,
                    "duration" : dataQuery.duration,
                    "url" : dataQuery.url,
                    "type" : dataQuery.typeads
                },  
                "client" : dataQuery.clientAMS.username      
            }
            ]
        else:
            output = [{
                "id" : dataQuery.id,
                "data" : {
                    "name" : dataQuery.name,
                    "duration" : dataQuery.duration,
                    "url" : dataQuery.url,
                    "type" : dataQuery.typeads
                },  
                "client" : None     
            }
            ]
        return make_response(jsonify(output), 200)

    
@app.route('/') 
def index():
    
    return 'Welcome To the Club'

api.add_resource(Userall, "/ams/register", methods=["POST","GET","DELETE"])
api.add_resource(Userid,"/ams/register/<id>", methods=["GET", "PUT", "DELETE"])

api.add_resource(ClientAmsall, "/ams/user", methods=["POST","GET","DELETE"])
api.add_resource(ClientAmsid, "/ams/user/<id>", methods=["PUT","GET","DELETE"])

api.add_resource(AdsAll, "/ams/ads", methods=["POST","GET","DELETE"])
api.add_resource(Adsid, "/ams/ads/<id>", methods=["PUT","GET","DELETE"])

api.add_resource(LoginUser, "/ams/login", methods=["POST"])
api.add_resource(LoginClient, "/ams/login/user", methods=["POST"])

api.add_resource(ClientRelation, "/ams/user/all", methods=['GET'])
api.add_resource(ClientRelationid, "/ams/user/all/<id>", methods=['GET'])

api.add_resource(AdsRelationAll, "/ams/ads/all", methods=['GET'])
api.add_resource(AdsRelationid, "/ams/ads/all/<id>", methods=['GET'])

if __name__ == "__main__":
    app.run(debug=True,port=2000, host="0.0.0.0")
