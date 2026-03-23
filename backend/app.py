import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from threat_model.engine import generate_threat_model

app = Flask(__name__, static_folder="../frontend/dist", static_url_path="")
CORS(app)

@app.route("/api/survey", methods=["POST"])
def receive_survey():
    data = request.get_json()
    if not data or "responses" not in data:
        return jsonify({"error": "Invalid payload"}), 400
    threat_model = generate_threat_model(data["responses"])
    return jsonify(threat_model)

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))