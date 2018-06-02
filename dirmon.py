import os,binascii
from random import shuffle
import requests
import sys
import time
import ssl
from Queue import Queue
from threading import Thread
import csv


### FUNCTIONS

### Calculate default response code
def getVerifiedResponse(protocol,host,port,path):
    status=None
    same=0
    c=0
    while True:
        c=c+1
        if (c>10):
            return [None]
        try:
            url=protocol+host+":"+str(port)+"/"+path
            data=requests.get(url, verify=False, allow_redirects=False, headers=useragent, timeout=5)
            if(status==data.status_code):
                same=same+1
                if (same==2):
                    dir=False
                    try:
                        if(path+'/' in data.headers['Location']):
                            dir=True
                    except:
                        pass
                    return [status,len(data.content),dir]
            else:
                same=0
                status=data.status_code
        except Exception as e:
            continue

### Scan for a file
def scan(protocol, host, port, path, code_whitelisted):
    #get default code again if number of false positives is high
    if(protocol+host+":"+str(port) in falsePositives):
        if(falsePositives[protocol+host+":"+str(port)]>maxFalsePositives):
            del falsePositives[protocol+host+":"+str(port)]
            del defaultResponses[protocol+host+":"+str(port)]
    #get default response status code
    if (protocol+host+":"+str(port) not in defaultResponses): 
        defaultResponses[protocol+host+":"+str(port)]=getVerifiedResponse(protocol,host,port,binascii.b2a_hex(os.urandom(15)))[0]
    defaultResponse=defaultResponses[protocol+host+":"+str(port)]
    if (defaultResponse==None or defaultResponse==999):
        deadHosts.append([protocol,host,port])
        return None
    #scan host
    for r in range(0, maxRetries):
        try:
            url=protocol+host+":"+str(port)+"/"+path
            #generate fake path
            split1=path.split('/')
            split2=split1[-1].split('.')
            if(split2[0]==""):
                split2[-1]=split2[-1]+"fake"
            else:
                split2[0]=split2[0]+"fake"
            split1[-1]='.'.join(split2)
            fakepath='/'.join(split1)
            #Get data
            data=requests.get(url, verify=False, allow_redirects=False, headers=useragent, timeout=5)
            statusCode=data.status_code
            #to avoid some trouble with yahoo responses
            if (statusCode==999):
                statusCode=defaultResponse
            if (statusCode==defaultResponse):
                return 'False Positive'
            else:
                #if status code is different from default status code, verify result
                verifiedResponse=getVerifiedResponse(protocol,host,port,path)
                if (verifiedResponse[0]==defaultResponse):
                    return None
                else:
                    #if result is verified, verify once more by comparing to result of fake request
                    fakeResponse=getVerifiedResponse(protocol,host,port,fakepath)
                    if (fakeResponse[0]==verifiedResponse[0]):
                        if (protocol+host+":"+str(port) not in falsePositives):
                            falsePositives[protocol+host+":"+str(port)]=0
                        falsePositives[protocol+host+":"+str(port)]=falsePositives[protocol+host+":"+str(port)]+1
                        return 'False Positive'
                    else:
                        status=verifiedResponse[0]
                        size=verifiedResponse[1]
                        dir=verifiedResponse[2]
                        if (code_whitelisted!='a' and dir==False):
                            if (str(status) not in code_whitelisted or status==404):
                                return 'Out of Scope'
                        return [protocol, host, str(port), path, str(size), dir, status, url]
            return None
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            if(r==maxRetries-1):
                deadHosts.append([protocol, host,port])
                return None
            continue
        except Exception as e:
            return None 


### Worker
def workers(q,):
    global totalRequests
    global totalDone
    global results
    global code_whitelisted
    while True:
        result=None
        # Get item from queue
        try:
            item=q.get()
            totalRequests=totalRequests-1
            totalDone=totalDone+1
        except:
            return None
        
        #custom port
        if(':' in item[0]):
            host=item[0].split(':')[0]        
            port=item[0].split(':')[1]
        else:
            host=item[0]
            port=443

        # Test https
        if(["https://", host,port] not in deadHosts):
            result=scan("https://",host,port,item[1],code_whitelisted) 
        # Test http
        if(port==443):
            port=80
        if (result==None):
            if(["http://", host,port] not in deadHosts):
                result=scan("http://",host,port,item[1],code_whitelisted)
        if (result!=None and result!=False and result!='Out of Scope' and result!='False Positive'):
            try:
                output(result[1], result[2], result[7], result[6], result[4], result[5], result[3])
            except Exception as e:
                pass
        q.task_done()

### Printing stats
def stats(run):
    elapsed_time = time.time() - start_time
    message="[Run "+str(run)+"][Endpoints remaining: "+str(totalRequests)+"][Endpoints done: "+str(totalDone)+"]"
    sys.stdout.write("\033[1;36m\r%s\033[0;0m" % message)
    sys.stdout.flush()

### Output data
def output(host, port, url, status, size, dir, path):
    r=[host, port, url, str(status), size, str(dir), path]
    if (r in results):
        return False
    else:
        if(dir==False):
            content="\r[Status: "+str(status)+"][Size: "+size+"]["+url+"]\033[K" #\033[K is for clearing line
        else:
            content="\r[DIRECTORY]["+url+"]\033[K" #\033[K is for clearing line
        print "{0}\n".format(content), 
        outputBuffer.put(r)
        results.append(r)

### Create queue
def createQueue(q):
    for w in wordlist:
        for h in hosts:
            q.put([h,w])
            while True:
                if (q.unfinished_tasks<10000):
                    break
                else:
                    time.sleep(1)

### Output buffer
def csvOutput(q):
    with open(r'results.csv', 'a') as f:
        writer = csv.writer(f)
        while True:
            try:
                o=q.get()
                writer.writerow(o)
            except:
                time.sleep(1)

###MAIN

### Global vars and settings

# Ignore ssl cert errors
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
requests.packages.urllib3.disable_warnings()

# Threading parameters
q = Queue(maxsize=0)
outputBuffer = Queue(maxsize=0)

deadHosts=[]

# User agent
useragent={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0'}

# Other params
maxRetries=5
defaultResponses={}
falsePositives={}
maxFalsePositives=100

banner="""  _____ _____ _____  __  __  ____  _   _ 
 |  __ \_   _|  __ \|  \/  |/ __ \| \ | |
 | |  | || | | |__) | \  / | |  | |  \| |
 | |  | || | |  _  /| |\/| | |  | | . ` |
 | |__| || |_| | \ \| |  | | |__| | |\  |
 |_____/_____|_|  \_\_|  |_|\____/|_| \_|
               ...dirmon v0.1 | stanko.sh

"""

# Print banner
sys.stdout.write("\033[1;31m%s\033[0;0m" % banner)
sys.stdout.flush()

# User input
num_threads = int(raw_input("Number of threads? [default: 10] ") or 10)
hosts_file = raw_input("Host list? [default: hosts.txt] ") or "hosts.txt"
wordlist_file = raw_input("Word list? [default: wordlist.txt] ") or "wordlist.txt"
code_whitelisted = raw_input("Status code(s) to look for - comma separated or 'a' for all [default:200]? ") or "200"
if (',' in code_whitelisted):
    code_whitelisted = code_whitelisted.split(',')
elif (code_whitelisted!='a'):
    code_whitelisted = [code_whitelisted]

# Read input

# Read hosts list
with open(hosts_file) as f:
    hosts = f.read().splitlines() 
shuffle(hosts)

# Read wordlist list
with open(wordlist_file) as f:
    wordlist = f.read().splitlines() 

# DIRMON started
sys.stdout.write("\033[0;32m\r\n* DIRMON running\r\n\r\n033[0;0m")
sys.stdout.flush()

# Read previous results
results=[]
f = open('results.csv', 'a+')
reader = csv.reader(f)
for row in reader:
    results.append(row)
f.close()

totalRequests=len(hosts)*len(wordlist)
totalDone=0

# Output to csv
queueWorker = Thread(target=csvOutput, args=(outputBuffer,))
queueWorker.setDaemon(True)
queueWorker.start()

run=1
while True:
    start_time = time.time()
    #print "Total subdomains: "+str(len(subdomains))

    # Create queue
    queueWorker = Thread(target=createQueue, args=(q,))
    queueWorker.setDaemon(True)
    queueWorker.start()
    #time.sleep(1) #to provide time for the queue to generate

    for i in range(num_threads):
        worker = Thread(target=workers, args=(q,))
        worker.setDaemon(True)
        worker.start()

    while True:
        if (q.unfinished_tasks!=0):
            stats(run)
        else:
            stats(run)
            break
        time.sleep(0.2)
        continue
    run=run+1
    deadHosts=[]
    totalDone=0
    totalRequests=len(hosts)*len(wordlist)
    q.join()