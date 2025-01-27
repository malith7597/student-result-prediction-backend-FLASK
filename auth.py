from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from models import db, User
import numpy as np
import pandas as pd
import pickle
from flask_cors import CORS, cross_origin
import datetime


bcrypt = Bcrypt()
auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    # Check if the user already exists
    if User.query.filter_by(username=username).first():
        return jsonify({"msg": "User already exists"}), 400

    # Create and save user
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    # Fetch user from database
    user = User.query.filter_by(username=username).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"msg": "Invalid username or password"}), 401

    access_token = create_access_token(identity=username,expires_delta=False)
    return jsonify({"access_token": access_token}), 200

@auth_bp.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"msg": f"Hello, {current_user}. This is a protected route."}), 200


with open("model.pkl", "rb") as file:
    model = pickle.load(file)


with open('ct_transformer.pkl', 'rb') as f:
    ct = pickle.load(f)


@auth_bp.route("/predict", methods=["POST"])
@jwt_required()
def predict():
    try:
        # Define the required fields with their default values
        required_fields = {
            "Gender": "",
            "Study Hours": 0,
            "Extracurricular_Involvement": "",
            "Part time job": "",
            "Struggle with English": "",
            "Year": "",
            "Previous_GPA": 0,
            "one_credit_course_1_ca": 0,
            "one_credit_course_1_attendance": 0,
            "one_credit_course_2_ca": 0,
            "one_credit_course_2_attendance": 0,
            "one_credit_course_3_ca": 0,
            "one_credit_course_3_attendance": 0,
            "one_credit_course_4_ca": 0,
            "one_credit_course_4_attendance": 0,
            "two_credit_course_1_ca": 0,
            "two_credit_course_1_attendance": 0,
            "two_credit_course_2_ca": 0,
            "two_credit_course_2_attendance": 0,
            "two_credit_course_3_ca": 0,
            "two_credit_course_3_attendance": 0,
            "two_credit_course_4_ca": 0,
            "two_credit_course_4_attendance": 0,
            "two_credit_course_5_ca": 0,
            "two_credit_course_5_attendance": 0,
            "two_credit_course_6_ca": 0,
            "two_credit_course_6_attendance": 0,
            "three_credit_course_1_ca": 0,
            "three_credit_course_1_attendance": 0,
            "three_credit_course_2_ca": 0,
            "three_credit_course_2_attendance": 0,
        }

        input_json = request.get_json()
        processed_json = []
        for item in input_json:
            processed_item = {**required_fields, **item}
            processed_json.append(processed_item)
        input_data = pd.DataFrame(processed_json)
        transformed = ct.transform(input_data)
        prediction = model.predict(transformed)
        y_prob_new = model.predict_proba(transformed)
        y_prob_new_percentages = y_prob_new * 100
        detailed_predictions = []
        for i, (pred, probs) in enumerate(zip(prediction, y_prob_new_percentages)):
            detailed_predictions.append({
                "data_point": i + 1,
                "predicted_class": "Pass" if pred == 1 else "Fail",
                "probability_pass": f"{probs[1]:.2f}%",
                "probability_fail": f"{probs[0]:.2f}%"
            })

        response = {
            "prediction": prediction.tolist(),
            "detailed_predictions": detailed_predictions,
        }
        return jsonify(response)

    except Exception as e:
        return jsonify({"error": str(e)}), 400
