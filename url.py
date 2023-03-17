import base64

url_id = base64.urlsafe_b64encode("http://google.com".encode()).decode().strip("=")
print(url_id)