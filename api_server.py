from flask import Flask, request, jsonify
from flask_cors import CORS

from utils.scan_controller import run_full_scan

app = Flask(__name__)
CORS(app)


@app.route("/")
def home():
    return "Synth Scan API Running"


@app.route("/scan", methods=["POST"])
def scan():

    try:
        data = request.json
        target = data.get("target")

        if not target:
            return jsonify({"error": "Target not provided"}), 400

        results = run_full_scan(target)

        response = {
            "risk_score": results.get("risk_score", 0),
            "severity": results.get("severity", "UNKNOWN"),
            "open_ports": results.get("open_ports", []),
            "directories": results.get("directories", []),
            "technologies": results.get("technologies", []),
            "vulnerabilities": results.get("vulnerabilities", [])
        }

        return jsonify(response)

    except Exception as e:
        return jsonify({
            "error": "Scan failed",
            "details": str(e)
        }), 500


if __name__ == "__main__":
    app.run(debug=True)