from flask import Flask
import numpy as np
from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import traceback
from flask_cors import CORS, cross_origin
import sklearn
from urllib.parse import urlparse
# from preprocessing import detect
from preprocessing_v2 import detect_phishing



app = Flask(__name__)
try:
    model = joblib.load('RFC_model.pkl')
except Exception as e:
    print(str(e))
cors = CORS(app)

with open('whitelist.txt') as f:
    whitelist = f.read().splitlines()

print(whitelist)

with open('blacklist.txt') as f:
    blacklist = f.read().splitlines()

print(blacklist)


app.config['CORS_HEADERS'] = 'Content-Type'

@app.route('/getprediction', methods=['GET', 'POST'])
@cross_origin()
def getprediction():
    if model:
        # detect_phishing(url)
        try:
            # get url from request query params
            url = request.args.get('url')
            domain = urlparse(url).netloc
            #check domain is in whitelist
            if domain in whitelist:
                return jsonify({'prediction': '[0]'})
            elif domain in blacklist:
                return jsonify({'prediction': '[1]'})
            else:
                features = detect_phishing(url)
                print(features)
                prediction = model.predict([features])
                print("prediction: ", prediction)
                return jsonify({'prediction': str(prediction)})
        except:
            return jsonify({'trace': traceback.format_exc()})

if __name__ == "__main__":
    app.run(threaded=True)
