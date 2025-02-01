from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient, errors
import uuid
import time
import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

app = Flask(__name__)
CORS(app)

try:
    client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=5000)
    db = client["test"]  # Uses demo for now
    userstorage = db["userx"]
    keystorage = db["keys"]
    client.admin.command('ping')
except errors.ServerSelectionTimeoutError:
    client = None

# Load private key into memory
with open("server_private.pem", "rb") as key_file:
    private_key_bytes = key_file.read()
server_private_key = RSA.import_key(private_key_bytes)




# decrypt request data
def decrypt_request(encrypted_data):
    try:
        cipher = PKCS1_OAEP.new(server_private_key)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data))
        return decrypted_data.decode()
    except Exception:
        return None

# validate UUID
def is_valid_uuid(uuid_string):
    try:
        return str(uuid.UUID(uuid_string, version=4)) == uuid_string
    except ValueError:
        return False

def compute_hash(key, salt):
    return hashlib.sha256((salt + key).encode()).hexdigest()

# Update key endpoint
@app.route("/user/<uuid>/update/<key>", methods=["POST"])
def update_key(uuid, key):
    if client is None:
        return jsonify({"error": "Database connection failed"}), 503

    if not is_valid_uuid(uuid):
        return jsonify({"error": "Invalid UUID format"}), 400

    encrypted_data = request.json.get("data")
    decrypted_key = decrypt_request(encrypted_data)
    
    if decrypted_key is None:
        return jsonify({"error": "Failed to decrypt data"}), 400
    
    user = userstorage.find_one({"_id": uuid})
    
    if not user:
        return jsonify({"error": "User not found"}), 404

    stored_salt = user.get("salt")
    stored_hash = user.get("key")
    
    new_hash = compute_hash(decrypted_key, stored_salt)

    if stored_hash:
        last_updated = user.get("lastUpdated", 0)
        current_time = int(time.time())

        # Update Timeout
        if current_time - last_updated < 86400:
            return jsonify({"error": "Key recently updated"}), 408
        
        userstorage.update_one(
            {"_id": uuid},
            {"$set": {"key": new_hash, "lastUpdated": current_time}}
        )
        return jsonify({"message": "Key updated"}), 202

    # key init
    if stored_hash is None:
        userstorage.update_one(
            {"_id": uuid},
            {"$set": {"key": new_hash, "lastUpdated": int(time.time()), "createdDate": int(time.time())}}
        )
        return jsonify({"message": "Key created"}), 201

    return jsonify({"error": "Unknown Keyfield"}), 403

@app.route("/user/<UUID>/publickey", methods=["GET"])
def get_public_key(identifier):
    if client is None:
        return jsonify({"error": "Database connection failed"}), 503
    
    if is_valid_uuid(identifier):
        user = userstorage.find_one({"_id": identifier}, {"_id": 0, "publicKey": 1})
    else:
        user = userstorage.find_one({"username": identifier}, {"_id": 0, "publicKey": 1})
    
    if user:
        return jsonify({"publicKey": user["publicKey"]})
    
    return jsonify({"error": "User not found"}), 404

@app.route("/authkey", methods=["GET"])
def get_auth_key():
    if client is None:
        return jsonify({"error": "Database connection failed"}), 503
    
    root_key = keystorage.find_one({"_id": "root", "keyOwner": "root"}, {"_id": 0, "keyValue": 1})
    
    if root_key:
        return jsonify({"status": 100, "serverPublicKey": root_key["keyValue"]})
    
    return jsonify({"error": "Root key not found"}), 404


if __name__ == "__main__":
    app.run(debug=False)
