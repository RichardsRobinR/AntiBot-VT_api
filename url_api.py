    # def get_url_id(self):

    #     url = 'https://www.virustotal.com/api/v3/urls'
    #     api_key = self.api_key

    #     website_url = "google.com"
    #     payload = "url={}".format(website_url)
    #     headers = {'x-apikey': api_key}

    #     response = requests.post(url, headers=headers, data=payload) 
    #     # print(response.json())
    #     jsonString = json.dumps(response.json())
    #     jsonFile = open("data_url.json", "w")
    #     jsonFile.write(jsonString)
    #     jsonFile.close()

    #     if response.status_code == 200:
    #         result = response.json()
    #         url_id = result['data']['id']
    #         print("URL scan ID:", url_id)
    #         return url_id
        
    #     else:
    #         print("Error :", response.status_code)


    # def url_analysis(self):