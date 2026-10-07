import base64
import os
import urllib.parse

v = os.environ["STRIPE_KEY"]
print("plain:", v)
print("b64:", base64.b64encode(v.encode()).decode())
print("b64nopad:", base64.b64encode(v.encode()).decode().rstrip("="))
print("hex:", v.encode().hex())
print("HEX:", v.encode().hex().upper())
print("url:", urllib.parse.quote(v, safe=""))
