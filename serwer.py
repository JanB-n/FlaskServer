import pymongo
import jwt
import datetime
import json
import hashlib
from functools import wraps
from flask import Flask, request, make_response
from flask_cors import CORS, cross_origin
from flask_restful import Api, Resource, reqparse, abort

app = Flask(__name__)
CORS(app)
api = Api(app)
app.config['CORS_HEADERS'] = 'Content-Type'
app.config['SECRET_KEY'] = "SecretKey"
try:
    mongo = pymongo.MongoClient("mongodb+srv://9baran:pass9baran@cluster0.hmiq5.mongodb.net/myFirstDatabase?retryWrites=true&w=majority")

    db = mongo.Sporty
    db.users.drop_indexes()
    db.users.create_index("login", unique=True)
    db.logs.drop_indexes()
    db.logs.create_index("data", unique=True)
    mongo.server_info()
except Exception as ex:
    print("Nie udalo sie polaczyc z baza danych")
    print(ex)


def jwt_token(f):
   @wraps(f)
   def decorated_function(*args, **kwargs):
        if request.method == "OPTIONS":
         
            response = make_response()
            response.headers.add("Access-Control-Allow-Origin", "*")
            response.headers.add('Access-Control-Allow-Headers', "*")
            response.headers.add('Access-Control-Allow-Methods', "*")
            print(response)
            return response
        # if not 'Authorization' in request.headers:
        #     abort(401)
        # data = request.headers['Authorization'].encode('ascii', 'ignore')
        # token = str.replace(str(data), 'Bearer ', '')
        token = request.get_json()['token'][1:-1]
        try:
            user = jwt.decode(token, app.config['SECRET_KEY'], algorithms="HS256")
        except Exception as e:
            print(e)
            abort(401)

        return f(*args, **kwargs)
   return decorated_function


@app.route("/logowanie", methods = ["POST"])
def logowanie():
    login = request.get_json()
    print('QWERTY: ', login)
    if db.users.count_documents({'login': login["login"], 'hash': hashlib.md5(login['password'].encode('utf-8')).hexdigest()}, limit = 1) == 1:    
        token = jwt.encode({'user' : login['login'], 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30) }, app.config['SECRET_KEY'], algorithm="HS256")
        return json.dumps({'success':True, 'token': token, 'user': login}), 200, {'ContentType':'application/json'}
    else:
        return json.dumps({'success':False}), 402, {'ContentType':'application/json'}

@app.route('/rejestracja', methods=["POST"])
def register():
   info = request.get_json()
   try:
      user = {"login":info['login'], "hash": hashlib.md5(info['password'].encode('utf-8')).hexdigest()}
      dbResponse = db.users.insert_one(user)
      id = dbResponse.inserted_id
      print(id)
      return json.dumps({'success':True}), 201, {'ContentType':'application/json'}
   except Exception as ex:
      print(ex)
      return json.dumps({'success':False, 'message':'Username already taken'}), 409, {'ContentType':'application/json'}


@app.route("/dodaj", methods =["POST", 'OPTIONS'])
@jwt_token
def add():
   
   try:
      v = request.get_json()
      log ={'rodzaj': v['rodzaj'], 'druzyna1':v['druzyna1'], 'druzyna2': v['druzyna2'], 'punkty1': v['punkty1'], 'punkty2': v['punkty2'], 'data': v['data']}
      db.logs.insert_one(log)
      print(log)
      return json.dumps({'success':True}), 201, {'ContentType':'application/json'}
   except Exception as ex:
      print(ex)
      return json.dumps({'success':False, 'message':'Log for that date aleready exist'}), 409, {'ContentType':'application/json'}

@app.route("/pokaz", methods =["POST"])
@jwt_token
def show():
   
   cursor = db.logs.find()
   list_cur = list(cursor)
   for x in list_cur:
      x["_id"] = str(x["_id"])

   return json.dumps({'success':True, 'list':json.dumps(list_cur)}), 201, {'ContentType':'application/json'}


if __name__ == "__main__":
    app.run(debug=True)
