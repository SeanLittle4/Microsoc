from flask import Flask, request, jsonify
from flask_cors import CORS
from threat_model.engine import generate_threat_model

app = Flask(__name__)
CORS(app)  # allows React dev server to talk to Flask

@app.route("/api/survey", methods=["POST"])
def receive_survey():
    data = request.get_json()
    if not data or "responses" not in data:
        return jsonify({"error": "Invalid payload"}), 400

    threat_model = generate_threat_model(data["responses"])
    return jsonify(threat_model)

if __name__ == "__main__":
    app.run(debug=True, port=5000)