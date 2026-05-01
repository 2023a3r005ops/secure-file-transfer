import requests
import os
import urllib3
urllib3.disable_warnings()

BASE_URL = "https://127.0.0.1:5000"
token = None

def register(username, password):
    r = requests.post(f"{BASE_URL}/register",
                      json={"username": username, "password": password},
                      verify=False)
    print("REGISTER:", r.json())

def login(username, password):
    global token
    r = requests.post(f"{BASE_URL}/login",
                      json={"username": username, "password": password},
                      verify=False)
    data = r.json()
    if "token" in data:
        token = data["token"]
        print("LOGIN: Successful! Token stored.")
    else:
        print("LOGIN FAILED:", data)

def upload(filepath):
    with open(filepath, "rb") as f:
        r = requests.post(
            f"{BASE_URL}/upload",
            headers={"Authorization": f"Bearer {token}"},
            files={"file": (os.path.basename(filepath), f)},
            verify=False
        )
    print("UPLOAD STATUS:", r.status_code)
    print("UPLOAD RESPONSE:", r.text)  # Show raw response

def list_files():
    r = requests.get(f"{BASE_URL}/files",
                     headers={"Authorization": f"Bearer {token}"},
                     verify=False)
    print("FILES:")
    for file in r.json():
        print(f"  [{file['id']}] {file['filename']} - {file['size']} bytes - {file['uploaded_at']}")

def download(file_id, save_as):
    r = requests.get(f"{BASE_URL}/download/{file_id}",
                     headers={"Authorization": f"Bearer {token}"},
                     verify=False)
    with open(save_as, "wb") as f:
        f.write(r.content)
    print(f"DOWNLOAD: Saved and decrypted to '{save_as}'")

if __name__ == "__main__":
    register("alice", "SecurePass123")
    login("alice", "SecurePass123")
    upload(r"C:\Secure File Transfer System (Encryption + Authentication)\client\testfile.txt")
    list_files()
    download(1, r"C:\Secure File Transfer System (Encryption + Authentication)\client\downloaded_file.txt")