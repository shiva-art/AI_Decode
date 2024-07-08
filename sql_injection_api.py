from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
from waitress import serve

app = Flask(__name__)
CORS(app)  # Allow Cross-Origin Resource Sharing

# Load the best model
model = joblib.load('best_xss_model_count_vectorizer_v1.pkl')

def predict_xss(sentences):
    return model.predict(sentences)[0]

@app.route('/note', methods=['POST'])
def check_note():
    note = request.json.get('note')

    # Predict XSS for the note
    prediction_xss = predict_xss([note.lower()])

    response = {
        "is_xss": bool(prediction_xss),
        "message": "No injection detected"
    }

    if response["is_xss"]:
        response["message"] = "XSS detected in note"
    return jsonify(response)

if __name__ == '__main__':
    serve(app, host='0.0.0.0', port=4090)
