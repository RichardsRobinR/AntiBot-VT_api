import requests
import hashlib
import json
from dotenv import load_dotenv
import os


class VirusTotalApi:

    def __init__(self):
        load_dotenv()  # load variables from .env file

        self.api_key = os.environ.get("API_KEY")    

    def check_file_is_malicious(self):
        file_id = self.get_file_ID()
        api_key = self.api_key
        url = 'https://www.virustotal.com/api/v3/files/{file_id}'

        headers = {'x-apikey': api_key}
        params = {'include': 'details'}

        response = requests.get(url.format(file_id=file_id), headers=headers, params=params)

        if response.status_code == 200:
            results = response.json()
            if results['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                print("The file is malicious.")
            else:
                print("The file is clean.")
        else:
            print("Error: {}".format(response.status_code))


    def get_file_ID(self):
        url = 'https://www.virustotal.com/api/v3/search'
        api_key = self.api_key
        query = self.get_file_hash()  #file_hash

        headers = {'x-apikey': api_key}
        params = {'query': query}

        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            results = response.json()
            # print(results['data'][0]['attributes'])

            # print(results['data'][0]['id'])
            # jsonString = json.dumps(results)
            # jsonFile = open("data.json", "w")
            # jsonFile.write(jsonString)
            # jsonFile.close()

            if results != '' :
                file_id = results['data'][0]['id']
                print("File ID: {}".format(file_id))
                return file_id
            else:
                print("File not found in VirusTotal.")
        else:
            print("Error: {}".format(response.status_code))


    def get_file_hash(self):

        file_path = 'sample.txt' #'/path/to/your/file'

        # Open the file in binary mode
        with open(file_path, 'rb') as f:
            file_contents = f.read()

        sha256_hash = hashlib.sha256(file_contents).hexdigest()
        return sha256_hash


    def file_analysis(self):

        api_key = self.api_key
        file_id = self.get_file_ID()
        url = 'https://www.virustotal.com/api/v3/files/{file_id}'

        headers = {'x-apikey': api_key}
        params = {'include': 'details'}

        response = requests.get(url.format(file_id=file_id), headers=headers, params=params)

        if response.status_code == 200:
            results = response.json()
            print("File name: {}".format(results['data']['attributes']['names'][0]))
            print("Size: {} bytes".format(results['data']['attributes']['size']))
            print("MD5 hash: {}".format(results['data']['attributes']['md5']))
            print("SHA-1 hash: {}".format(results['data']['attributes']['sha1']))
            print("SHA-256 hash: {}".format(results['data']['attributes']['sha256']))
            print("Last analysis date: {}".format(results['data']['attributes']['last_analysis_date']))
            print("Total number of antivirus engines: {}".format(len(results['data']['attributes']['last_analysis_results'])))
            for engine, result in results['data']['attributes']['last_analysis_results'].items():
                print("{}: {}".format(engine, result['result']))
        else:
            print("Error: {}".format(response.status_code))


    def get_url_id(self):

        url = 'https://www.virustotal.com/api/v3/urls'
        api_key = self.api_key

        website_url = "google.com"
        payload = "url={}".format(website_url)
        headers = {'x-apikey': api_key}

        response = requests.post(url, headers=headers, data=payload)
        # print(response.json())
        jsonString = json.dumps(response.json())
        jsonFile = open("data_url.json", "w")
        jsonFile.write(jsonString)
        jsonFile.close()

        if response.status_code == 200:
            result = response.json()
            url_id = result['data']['id']
            print("URL scan ID:", url_id)
            return url_id
        
        else:
            print("Error :", response.status_code)


    def url_analysis(self):

            api_key = self.api_key
            url_id = self.get_url_id()
            url = 'https://www.virustotal.com/api/v3/analyses/{url_id}'

            headers = {'x-apikey': api_key}
            params = {'include': 'allinfo'}

            response = requests.get(url.format(url_id=url_id), headers=headers, params=params)

            if response.status_code == 200:
                results = response.json()
                print("Url info: {}".format(results['meta']['url_info']['url']))
                # print("Last analysis date: {}".format(results['data']['attributes']['last_analysis_date']))
                print("Total number of antivirus engines: {}".format(len(results['data']['attributes']['results'])))
                for engine, result in results['data']['attributes']['results'].items():
                    print("{}: {}".format(engine, result['result']))
            else:
                print("Error: {}".format(response.status_code))

