import numpy as np
from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import traceback
from flask_cors import CORS, cross_origin


app = Flask(__name__)
model = joblib.load('SVM_model.pkl')
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

@app.route('/getprediction', methods=['GET', 'POST'])

@cross_origin()
def getprediction():
    if model:
        try:
            json_ = request.json
            final_input = np.array(json_["data"])
            prediction = model.predict([final_input])
            return jsonify({'prediction': str(prediction)})
        
        except:
            return jsonify({'trace': traceback.format_exc()})
        

if __name__ == '__main__':
    app.run(port=1234, debug=True)