import vt
import time

api_key = "080c39699749b3d8c153e20cf1c813e9c96dbf2fe14bc57ff045f33f5ec20fa0"

client = vt.Client(api_key)

# analysis = client.scan_url('https://google.com')
# print(analysis)

# with open("sample.txt", "rb") as f:
#     analysis = client.scan_file(f, wait_for_completion=True)
    
#     # print(str(analysis))
#     # analysis_list = str(analysis).split()
#     # print(analysis_list)

# analysis = client.get_object("/analyses/{}", analysis.id)
# print(analysis.status)
# print(analysis.last_analysis_results)


with open("sample.txt", "rb") as f:
    analysis = client.scan_file(f)


while True:
    analysis = client.get_object("/analyses/{}", analysis.id)
    print(analysis.status)
    if analysis.status == "completed":
        break
    time.sleep(30)

print(analysis.last_analysis_results)
# file = client.get_object(analysis_list[1])
# print(file)

# url_id = vt.url_id("http://www.virustotal.com")
# url = client.get_object("/urls/{}", url_id)
# print(url.last_analysis_stats)
client.close()

# import requests

# url = "https://www.virustotal.com/api/v3/files"

# files = {"file": ("text_data.txt", open("text_data.txt", "rb"), "text/plain")}
# headers = {
#     "accept": "application/json",
#     "x-apikey": "080c39699749b3d8c153e20cf1c813e9c96dbf2fe14bc57ff045f33f5ec20fa0"
# }

# response = requests.post(url, files=files, headers=headers)

# print(response.text)