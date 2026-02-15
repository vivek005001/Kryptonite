from pyngrok import ngrok
from dotenv import load_dotenv
import os

load_dotenv()

auth_token = os.getenv("NGROK_AUTH_TOKEN")
ngrok.set_auth_token(auth_token)

tunnel = ngrok.connect(8000, hostname="cool-starfish-suitable.ngrok-free.app")

with open('tunnel_url.txt', 'w') as f:
    f.write(tunnel.public_url)

print(tunnel.public_url)

import time

while True:
    time.sleep(10)

with open('tunnel_url.txt', 'w') as f:
    f.write(tunnel.public_url)

print(tunnel.public_url)

import time

while True:
    time.sleep(10)