# middleware/authentication.py

from flask import request, jsonify
import jwt
import os

def authentication(view_function):
    def wrapper(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({"message": "No token provided, Please Login."}), 401

        # Assuming you have the secret key stored in an environment variable named "JWT_SECRET_KEY"
        # secret_key = os.getenv("JWT_SECRET_KEY")

        try:
            # Decode the JWT token using the provided secret key
            decoded_token = jwt.decode(token, 'shubham', algorithms=["HS256"])
            print(decoded_token)
            # You can perform additional checks or operations related to authentication here.

            # Call the original view function with the decoded token as an argument (if needed).
            return view_function(decoded_token, *args, **kwargs)
        except jwt.ExpiredSignatureError:
            # The token has expired.
            return jsonify({"message": "Token has expired, Login again."}), 401
        except jwt.InvalidTokenError:
            # The token is invalid or malformed.
            return jsonify({"message": "Invalid token, Please login again"}), 401

    return wrapper