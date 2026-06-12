import os
import requests
import pathlib

git_file = pathlib.Path(".gitignore")
if git_file.exists():
    os.remove(git_file)
    print(".gitignore deleted successfully.")
else:
    print(".gitignore does not exist. Good.")

# Verify that the endpoint works and recreates it
url = "http://127.0.0.1:8002/security/fix/env_commit_risk"
print(f"Calling endpoint: {url}")
try:
    r = requests.post(url)
    print(f"Status Code: {r.status_code}")
    print(f"Response: {r.text}")
    
    # Check if .gitignore was created
    if git_file.exists():
        print("SUCCESS! .gitignore was automatically created by the backend auto-fix endpoint!")
        print("Content of .gitignore:")
        print(git_file.read_text(encoding="utf-8"))
    else:
        print("FAILED: .gitignore was not created.")
except Exception as e:
    print(f"Request failed: {e}")
