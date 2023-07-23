from flask import Flask, jsonify, request
import os
import openai
from openai.error import RateLimitError
from dotenv import load_dotenv
from pymongo import MongoClient
import bcrypt
import jwt
from flask_cors import CORS
from configs.connection import get_db_connection
from middleware.authentication import authentication


# Load environment variables from the .env file
load_dotenv()

app = Flask(__name__)
CORS(app)  # This will enable CORS for your entire app


@app.route("/")
def index():
    return "welcome to our backend"


# chatbot
openai.api_key = os.getenv("OPENAI_API_KEY")


@app.route("/gpt4", methods=["GET", "POST"])
@authentication
def gpt4(decoded_code):

    data = request.json
    user_input = data['user_input']
    email  = data['email']
    messages = [
        {
            "role": "assistant",
            "content": "You are a male parenting influencer with expertise in solving various parenting challenges. Your goal is to answer user questions in the same language they use and respond with a human-like tone, replicating the user's style. Ask clarifying questions to parents if needed.",
        },
        
    ]

    messages.extend(user_input)

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo", messages=messages,
            temperature=0.8,
            max_tokens=150
        )
        content = response.choices[0].message["content"]
    except RateLimitError:
        content = "The server is experiencing a high volume of requests. Please try again later."


    #insert latest response to user input
    user_input.append({'role':"assistant",'content':content})

    histories={
        "email":email,
        "histories":user_input
    }
    # Connect to the MongoDB database
    db = get_db_connection()

    # Get the "histories" collection
    histories_collection = db.histories
    histories_collection.delete_one({'email':email})
    histories_collection.insert_one(histories)
    
    return jsonify(content=content)

# chatbot end


@app.route('/history',methods=['POST'])
def history():
    email=request.json['email']
    # Connect to the MongoDB database
    db = get_db_connection()
    histories_collection = db.histories
    history=histories_collection.find_one({'email':email})

    if history:
        return jsonify({'message':'Chat history has been retrieved successfully.','history':history['histories'],'success':True})
    
    else:
        return jsonify({'message':'No Chat history available, Please login first', 'success':False})




@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Connect to the MongoDB database
    db = get_db_connection()

    # Get the "users" collection
    users_collection = db.users

    # Find the user with the given email in the "users" collection
    user = users_collection.find_one({'email': email})

    if user and bcrypt.checkpw(password.encode('utf-8'), user['password']):
        # Generate a JWT token upon successful login
        token = jwt.encode({'email':user['email']}, 'shubham', algorithm='HS256')

        return jsonify({'message': 'Login successful!', 'token': token, 'email':user['email']})
    
    else:
        return jsonify({'message': 'Invalid credentials. Please try again.'})


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    # Hash the password before storing it in the database
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Connect to the MongoDB database
    db = get_db_connection()

    # Get the "users" collection
    users_collection = db.users

    # Check if the email already exists in the "users" collection
    if users_collection.find_one({'email': email}):
        return jsonify({'message': 'Email already exists. Please choose a different email.'}), 409

    # Insert the new user details into the "users" collection
    user_data = {
        'email': email,
        'password': hashed_password
    }
    users_collection.insert_one(user_data)

    return jsonify({'message': f'Registration successful for email: {email}'})



if __name__ == "__main__":
    app.run(debug=True)
