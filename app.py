from flask import Flask
import numpy as np
from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
import traceback
from flask_cors import CORS, cross_origin
import sklearn
from tld import get_tld
from preprocessing_v2 import detect_phishing
from azure.storage.blob import BlobServiceClient, ContentSettings, BlobType

# Azure Blob Storage credentials
connect_str = 'DefaultEndpointsProtocol=https;AccountName=phishingdetectorstorage;AccountKey=6tIBbQBjw0fFxkrkJVfiFGbOwIBY5iL3kq0oaH2kQTCHyEJPa4OWuj3gy1vL/3VKLaRlJnPMiLo++ASt6gr8hg==;EndpointSuffix=core.windows.net'
blob_service_client = BlobServiceClient.from_connection_string(connect_str)
container_client = blob_service_client.get_container_client('list')
blob_client = container_client.get_blob_client('report_url.txt')

app = Flask(__name__)
try:
    model = joblib.load('RFC_model.pkl')
except Exception as e:
    print(str(e))
cors = CORS(app)

with open('whitelist.txt') as f:
    whitelist = f.read().splitlines()

with open('blacklist.txt') as f:
    blacklist = f.read().splitlines()

app.config['CORS_HEADERS'] = 'Content-Type'


@app.route('/getprediction', methods=['GET'])
@cross_origin()
def getprediction():
    if model:
        try:
            url = request.args.get('url')
            url = url.lower()
            domain = get_tld(url, as_object=True).fld
            # check domain is in whitelist
            if domain in whitelist:
                return jsonify({'prediction': '[0]'})
            elif domain in blacklist:
                return jsonify({'prediction': '[1]'})
            else:
                features = detect_phishing(url)
                prediction = model.predict([features])
                return jsonify({'prediction': str(prediction)})
        except:
            return jsonify({'trace': traceback.format_exc()})


@app.route('/postreporturl', methods=['POST'])
@cross_origin()
def postreporturl():
    url = request.args.get('url')
    # send url to report_url.txt on Azure Blob Storage
    try:
        report_url_content = blob_client.download_blob().readall().decode('utf-8')
        report_url_list = report_url_content.splitlines()
        if url not in report_url_list:
            blob_client.upload_blob(url + '\n', blob_type=BlobType.AppendBlob, overwrite=False,
                                    content_settings=ContentSettings(content_type='text/plain'))
        return jsonify({'message': 'success'})
    except Exception as e:
        return jsonify({'message': str(e)}) 


if __name__ == "__main__":
    app.run(threaded=True)
