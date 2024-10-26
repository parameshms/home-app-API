import certifi

from pymongo.errors import PyMongoError
import traceback
from flask import Flask, request, jsonify
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token
from pymongo import MongoClient
import datetime
import os
from dotenv import load_dotenv
from flask_cors import CORS
import re  
from bson import ObjectId 
load_dotenv()


app = Flask(__name__)
bcrypt = Bcrypt(app)
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET')
jwt = JWTManager(app)
CORS(app)
client = MongoClient(os.getenv('DB_URL'),tlsCAFile=certifi.where())

db = client['Authentication'] 
users = db['users']


@app.route('/register', methods=['POST'])
def register_user():
    try:
        data = request.json
        firstname = data.get('firstname')
        lastname = data.get('lastname')
        building_name = data.get('building_name')
        flat_no = data.get('flat_no')
        email = data.get('email')
        password = data.get('password')

        if not all([firstname, lastname, building_name, flat_no, email, password]):
            return jsonify({"error": "All fields are required."}), 400

        if users.find_one({'email': email}):
            return jsonify({"error": "Email already registered"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user_data = {
            'firstname': firstname,
            'lastname': lastname,
            'email': email,
            'password': hashed_password
        }

        result = users.insert_one(user_data)
        user_id = str(result.inserted_id)

        home_db = client['homes_db']
        homes_collection = home_db['homes']
        
        existing_home = homes_collection.find_one({
            'building_name': building_name, 
            'flat_no': flat_no
        })

        if existing_home:
            return jsonify({"message": "User registered successfully!", "home": "Home already exists."}), 201

        new_home = {
            'building_name': building_name,
            'flat_no': flat_no,
            'created_by': user_id,
            'created_at': datetime.datetime.utcnow()
        }
        
        homes_collection.insert_one(new_home)

        return jsonify({"message": "User registered successfully!", "home": "Home added successfully!"}), 201

    except Exception as e:
       
        print(f"Error occurred during registration: {e}")
        return jsonify({"error": "An error occurred during registration. Please try again later."}), 500


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.json
        username = data.get('email')
        password = data.get('password')
        if not username or not password:
            return jsonify({"error": "Missing email or password"}), 400

        if re.match(r"[^@]+@[^@]+\.[^@]+", username):
            user = users.find_one({"email": username})

            if not user:
                return jsonify({"error": "Invalid user"}), 400

            if not bcrypt.check_password_hash(user['password'], password):
                return jsonify({"error": "Invalid password"}), 400

            home_db = client['homes_db']
            homes_collection = home_db['homes']
            home = homes_collection.find_one({'created_by': str(user['_id'])})

            home_id = str(home['_id']) if home else None

            token = create_access_token(
                identity={'userId': str(user['_id']), 'role': "Owner", 'homeId': home_id}, 
                expires_delta=datetime.timedelta(hours=1)
            )

            return jsonify({
                "Message": "Login success", 
                "token": token, 
                "username": user['firstname'] + " " + user['lastname'],  # Combine firstname and lastname for display
                "role": "Owner",
                "homeId": home_id
            }), 200

 
        else:
          
            househelp_db = client['househelp_db']
            categories_collection = househelp_db['categories']
            househelps = househelp_db['househelps']
       
            maids = list(househelps.find({"personal_info.name": username}))

            if len(maids) == 0:
                return jsonify({"error": "Invalid maid"}), 400
           
            for maid in maids:
                pin = str(maid['pin'])
             
                if password == pin:
                  
                    maid_id = maid['_id']
                    roleID = maid.get('category_id')

                    role = categories_collection.find_one({"_id": ObjectId(roleID)})

                    if not role:
                        return jsonify({"error": "Role not found"}), 400

                    home_id = str(maid['homeId']) if 'homeId' in maid else None

                    token = create_access_token(
                        identity={'userId': str(maid_id), 'role': role['category_name'], 'homeId': home_id}, 
                        expires_delta=datetime.timedelta(hours=2)
                    )

                    return jsonify({
                        "Message": "Login success", 
                        "token": token, 
                        "username": maid['personal_info']['name'], 
                        'homeId': home_id,  
                        'role': role['category_name']
                    }), 200

                return jsonify({"error": "Invalid PIN"}), 400

    except PyMongoError as e:
        print(f"Database error: {e}")
        return jsonify({"error": "Database error, please try again later."}), 500

    except Exception as e:

        print(f"Unexpected error: {e}")
        traceback.print_exc()  
        return jsonify({"error": "An unexpected error occurred, please try again later."}), 500





if __name__ == '__main__':
    app.run(host='0.0.0.0',debug=True,port=5052)
