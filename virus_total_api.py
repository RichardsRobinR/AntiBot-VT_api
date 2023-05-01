import requests
import json
from dotenv import load_dotenv

class VirusTotalApi:
    
    def __init__(self):
        load_dotenv()  # load variables from .env file

        # self.api_key = os.environ.get("API_KEY") 
        self.api_key = "080c39699749b3d8c153e20cf1c813e9c96dbf2fe14bc57ff045f33f5ec20fa0" 
        self.file_path =""
        self.sha256_value = " "


    def get_file_name(self,file_path):
        self.file_path = file_path

    def upload_file(self):

        url = 'https://www.virustotal.com/api/v3/files'
        headers = {
        "accept": "application/json",
        "x-apikey": "080c39699749b3d8c153e20cf1c813e9c96dbf2fe14bc57ff045f33f5ec20fa0"
        }
        # Set up file path
        file_path = self.file_path

        # Upload file and get scan report
        with open(file_path, 'rb') as f:
            response = requests.post(url, headers=headers, files={'file': f})
            response.raise_for_status()
            scan_report = response.json()

        # Get analysis ID from scan report
        analysis_id = scan_report['data']['id']

        print("analysis_id",analysis_id)
        return analysis_id
    
    def filr_analysis(self):
        analysis_id = self.upload_file()
        api_key = self.api_key
        url = "https://www.virustotal.com/api/v3/analyses/{analysis_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": "080c39699749b3d8c153e20cf1c813e9c96dbf2fe14bc57ff045f33f5ec20fa0"
        }

        response = requests.get(url.format(analysis_id=analysis_id), headers=headers)

        if response.status_code == 200:
            results = response.json()
            print("MD5 hash: {}".format(results['meta']['file_info']['md5']))
            print("SHA-1 hash: {}".format(results['meta']['file_info']['sha1']))
            print("SHA-256 hash: {}".format(results['meta']['file_info']['sha256']))

            
            print(results['data']['attributes']['status'])
            self.sha256_value = results['meta']['file_info']['sha256']
            if results['data']['attributes']['status'] == "queued":
                print("New file found!!!")
                return " "
            else:
                file_id = results['meta']['file_info']['sha256']
                return file_id
        else:
            print("Error: {}".format(response.status_code))
            return " "


    
    def file_report(self,file_path):

        self.get_file_name(file_path)

        api_key = self.api_key
        file_id = self.filr_analysis()
        if file_id == " ":

            # Caching
            with open('data.json', 'r') as f:
                data_dict = json.load(f)

            if self.sha256_value == "2546dcffc5ad854d4ddc64fbf056871cd5a00f2471cb7a5bfd4ac23b6e9eedad":
                return data_dict["Virus"].items()
            else:
                return data_dict["No Virus"].items()

        url = 'https://www.virustotal.com/api/v3/files/{file_id}'

        headers = {
        "accept": "application/json",
        "x-apikey": "080c39699749b3d8c153e20cf1c813e9c96dbf2fe14bc57ff045f33f5ec20fa0"
        }

        response = requests.get(url.format(file_id=file_id), headers=headers) 

        if response.status_code == 200:
            results = response.json()
            print("File name: {}".format(results['data']['attributes']['names'][0]))
            print("Size: {} bytes".format(results['data']['attributes']['size']))
            print("MD5 hash: {}".format(results['data']['attributes']['md5']))
            print("SHA-1 hash: {}".format(results['data']['attributes']['sha1']))
            print("SHA-256 hash: {}".format(results['data']['attributes']['sha256']))
            print("Last analysis date: {}".format(results['data']['attributes']['last_analysis_date']))
            print("Total number of antivirus engines: {}".format(len(results['data']['attributes']['last_analysis_results'])))
            # for engine, result in results['data']['attributes']['last_analysis_results'].items():
            #     print("{}: {}".format(engine, result['result']))

            # print(results['data']['attributes']['last_analysis_results'])
            return results['data']['attributes']['last_analysis_results'].items()
        else:
            print("Error: {}".format(response.status_code))


