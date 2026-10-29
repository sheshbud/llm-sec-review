from flask import Flask, request, jsonify
app = Flask(__name__)
DB = {}

@app.route("/invoice")
def invoice():
    inv_id = request.args.get("id")
    return jsonify(DB[inv_id])
