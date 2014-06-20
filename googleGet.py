from urllib.parse import urlencode
from datetime import datetime
from urllib.request import build_opener

#get key from: https://developers.google.com/safe-browsing/key_signup
gsb_api_key = 'API KEY GOES HERE'
name = "GSB"
version = "1.0"
#this is the path for the URL containing the URLs seperated by new lines
path = "urllist.txt"

#bolds exception and malware in terminal
start = "\033[1m"
end = "\033[0;0m"

#vars
dateTimeNow = datetime.now()

#open text file containing URLs
with open(path, 'r') as file:
    text = file.read().splitlines()
file.close()
count = len(text)

#parameters for URL in get request
req = {}
req["client"] = name
req["appver"] = version
req["pver"] = "3.0"
req["apikey"] = gsb_api_key


def sendUrl(sentCount):
    """send each URL to google"""
    while (sentCount < count):
        sentCount += 1
        url = text.pop(0)
        #add url to get parameters
        req["url"] = url
        params = urlencode(req)
        req_url = "https://sb-ssl.google.com/safebrowsing/api/lookup?"+params
        opener = build_opener()
        response = opener.open(req_url)
        result = response.read().decode("utf-8")
        #warning: google returns invalid URLs as ""
        if result == "":
            print (str(sentCount) + " safe: " + url)
            resultFile = ("safe: " + url + "\n")
        else:
            print (str(sentCount) + " " + start + result + end + ": " + url)
            resultFile = (result + ": " + url + "\n")
        saveToFile(resultFile)
        if sentCount == count:
            print("Analyzing results.")
            analyzeFile()


def saveToFile(result):
    """save each result to file"""
    log = open("getLog{0}.txt".format(dateTimeNow), "a")
    log.write(result)
    log.close()


def analyzeFile():
    """when all URLs are tested, save analysis to file"""
    totalMalware = 0
    totalExc = 0
    logFile = open("getLog{0}.txt".format(dateTimeNow), "r+")
    #print("Analyzing and saving to file.")
    tempLog = logFile.read()
    for line in tempLog.splitlines()[:]:
        if "malware" in line:
            totalMalware += 1
    analysis = ("\nMalware Associated URLs: " + str((totalMalware / count) * 100) + "% " +
                str(totalMalware) + " / " + str(count) + "\nValid URLs: " +
                str(((count - totalMalware) / count) * 100) + "% " + str(count - totalMalware) + " / " + str(count))
    saveToFile(analysis)

#begin
sendUrl(0)
#print("Complete.")
