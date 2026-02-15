import requests

url = "https://cool-starfish-suitable.ngrok-free.app/analyze"
files = {'file': open('/home/teaching/Kryptonite/apps/DVIA-v2-swift.ipa', 'rb')}
response = requests.post(url, files=files)
print("Status Code:", response.status_code)
print("Response:", response.json())