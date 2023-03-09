# The following example uses Python and the Flask framework to verify a webhook request:
from flask import Flask, request, abort
import hmac
import hashlib
import base64
import os
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)

CLIENT_SECRET = os.getenv('SHOPIFY_API_SECRET_KEY')
def verify_webhook(data, hmac_header):
    digest = hmac.new(CLIENT_SECRET.encode('utf-8'), data, digestmod=hashlib.sha256).digest()
    computed_hmac = base64.b64encode(digest)

    return hmac.compare_digest(computed_hmac, hmac_header.encode('utf-8'))


@app.route('/webhook', methods=['POST'])
def handle_webhook():
    print("Request has been recieved !", flush=True)
    data = request.get_data()
    verified = verify_webhook(data, request.headers.get('X-Shopify-Hmac-SHA256'))
    if not verified:
        abort(401)

    # Process webhook payload
    # ...
    return ('', 200)

if __name__ == '__main__':
    app.run()