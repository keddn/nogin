from flask import Flask, request, render_template
import requests, time
from hmac import new
from hashlib import sha1
from base64 import b64encode
from secrets import token_hex

app = Flask(__name__)

PREFIX = bytes.fromhex("52")
DEVICE_KEY = bytes.fromhex("AE49550458D8E7C51D566916B04888BFB8B3CA7D")
SIGNATURE_KEY = bytes.fromhex("EAB4F1B9E3340CD1631EDE3B587CC3EBEDF1AFA9")

def device_id():
    encoded_data = sha1(token_hex(20).encode('utf-8')).hexdigest()
    digest = new(DEVICE_KEY, PREFIX + bytes.fromhex(encoded_data), sha1).hexdigest()
    return f"{PREFIX.hex()}{encoded_data}{digest}".upper()

def update_device(device: str):
    encoded_data = sha1(bytes.fromhex(device[2:42])).hexdigest()
    digest = new(DEVICE_KEY, PREFIX + bytes.fromhex(encoded_data), sha1).hexdigest()
    return f"{PREFIX.hex()}{encoded_data}{digest}".upper()

def signature(data: str):
    sig = [PREFIX[0]]
    sig.extend(new(SIGNATURE_KEY, str(data).encode("utf-8"), sha1).digest())
    return b64encode(bytes(sig)).decode("utf-8")

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        device = update_device(device_id())
        payload = {
            "email": email,
            "secret": f"0 {password}",
            "deviceID": device,
            "clientType": 300,
            "action": "normal",
            "timestamp": int(time.time() * 1000)
        }

        sig = signature(str(payload).replace("'", '"'))
        headers = {
            "NDCDEVICEID": device,
            "NDC-MSG-SIG": sig,
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 12; com.narvii.amino.master/3.5.35071)",
            "Content-Type": "application/json; charset=utf-8",
            "Accept-Language": "en-US"
        }

        res = requests.post(
            "https://service.aminoapps.com/api/v1/g/s/auth/login",
            json=payload,
            headers=headers
        )
        try:
            result = res.json()
        except:
            result = {"status_code": res.status_code, "text": res.text}

    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)