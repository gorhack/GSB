GSB
===

Google Safe Browsing API Python 3.x

Program utilizes the Google Safe Browsing API to send either Get (one URL at a time) or Push (10k requests @ 500 URLs per request) requests to check for malware in links. The push request opens a text file with URLs seperated by LF (new line). Google returns a file containing the response which is then saved to a seperate text file. 

Since URLs must be valid when sent to Google this python script validates each URL. If validation is not needed the for loop can be removed. 