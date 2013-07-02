from urllib.parse import urlencode
from urllib.request import build_opener
from urllib.request import Request
from datetime import datetime
import os

#get key from: https://developers.google.com/safe-browsing/key_signup
gsb_api_key = 'API KEY GOES HERE'
name = "GSB"
version = "1.5.2"
#this is the path for the URL containing the URLs seperated by new lines
path = "urllist.txt"

#parameters for URL in post request
req = {}
req["client"] = name
req["apikey"] = gsb_api_key
req["appver"] = version
req["pver"] = "3.0"
param = urlencode(req)

#bolds exception in terminal
#start = "\033[1m"
#end = "\033[0;0m"

#vars
dateTimeNow = datetime.now()

#construct URL
url = 'https://sb-ssl.google.com/safebrowsing/api/lookup?' + param

#open text file containing URLs
with open(path, 'r') as file:
    text = file.read().splitlines()
totalCount = len(text)

"""create Post body"""
def postBodyCreator(workingCount, body):
    #500 max number of URLs per request
    if len(text) > 500: 
        workingCount = text[0:500]
        del text[0:500]
    else:
        workingCount = text[0:len(text)]
        del text[0:len(text)]
    for currenturl in workingCount[:]:
        body+=currenturl + "\n"
    sendUrl(body, len(workingCount))
    if len(text) > 0: postBodyCreator(workingCount, '')
    else: analyzeFile()

"""sends formatted Post Request to Google API"""
def sendUrl(body, numberOfUrls):
    #POST parameters **On Mac Python 3.1 remove .encode() if error; on Linux Python 3.3 .encode() is required**
    postBody = (str(numberOfUrls) + "\n" + body).encode()
    # create your HTTP request **sometimes 403 errors so change userAgent**
    request = Request(url, postBody)
    # submit your request
    #print("Sent to Google.")
    res = build_opener().open(request)
    #print("Retrieved file from Google.")
    html = res.read().decode("utf-8")
    res.close()
    if not html: 
        for i in range(0, numberOfUrls): html+="ok"
    # save retrieved HTML to file
    saveToFile(html)

"""saves google's return values to file"""
def saveToFile(html):
    #print("Saving to file.")
    html+="\n"
    #open necessary files to save
    logFile = open("postLog_{0}_{1}.txt".format(os.path.splitext(path)[0],dateTimeNow), "a")
    logFile.write(html)
    logFile.close()
    #print("Check Point.")

"""analyzes file to determine percentage of malware related URLs"""
def analyzeFile():
    totalMalware = 0
    logFile = open("postLog_{0}_{1}.txt".format(os.path.splitext(path)[0],dateTimeNow), "r+")
    #print("Analyzing and saving to file.") 
    tempLog = logFile.read()
    for line in tempLog.splitlines()[:]:
        if line == "malware": totalMalware+=1
    analysis="\nMalware Associated URLs: " + str((totalMalware / (totalCount)) * 100) + "% " + str(totalMalware) + " / " + str(totalCount) +"\nValid URLs: " + str(((totalCount - totalMalware) / (totalCount)) * 100) + "% " + str(totalCount - totalMalware) + " / " + str(totalCount)
    logFile.write(analysis)
    #close files
    logFile.close()

#begin
postBodyCreator([], '')
#print("Complete.")
