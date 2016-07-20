#!/usr/bin/env python

'''
Python CLI-tool (without need for a GUI) to measure Internet speed with fast.com

'''


import os
import json
import urllib
import urllib2
import sys
import socket
import time
from threading import Thread


def threadThis(url, result, index):
    '''
    get the stuff from url in chuncks of size CHUNK, and keep writing the number of bytes retrieved into result[index]
    '''
    # print url, index, result[index]
    req = urllib2.urlopen(url)
    CHUNK = 100 * 1024
    i = 1
    while True:
        chunk = req.read(CHUNK)
        if not chunk:
            break
        result[index] = i * CHUNK
        i = i + 1


class fast:
    '''
    Python module to measure Internet speed with fast.com
    '''

    forceipv4 = False
    forceipv6 = False
    verbose = False
    maxtime = 15

    def __init__(self, verbose=False, maxtime=15, forceipv4=False, forceipv6=False):
        '''
                verbose: print debug output
                maxtime: max time in seconds to monitor speedtest 
                forceipv4: force speed test over IPv4
                forceipv6: force speed test over IPv6
        '''
        self.verbose, self.maxtime, self.forceipv4, self.forceipv6 = (
            verbose, maxtime, forceipv4, forceipv6)

    def fetchToken(self):
        '''Fetches a token from an obuscated js file'''
        # go to fast.com to get the javascript file
        url = 'https://fast.com/'
        try:
            urlresult = urllib.urlopen(url)
        except:
            # no connection at all?
            raise("Unable to get a token")

        response = urlresult.read()
        for line in response.split('\n'):
            # We're looking for a line like '<script
            # src="/app-40647a.js"></script>'
            if line.find('script src') >= 0:  # At time of writing: '/app-40647a.js'
                jsname = line.split('"')[1]

        # From that javascript file, get the token:
        url = 'https://fast.com' + jsname
        if self.verbose:
            print "javascript url is", url
        urlresult = urllib.urlopen(url)
        allJSstuff = urlresult.read()  # this is a obfuscated Javascript file

        # We're searching for the "token:" in this string:
        # .dummy,DEFAULT_PARAMS={https:!0,token:"YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm",urlCount:3,e

        for line in allJSstuff.split(','):
            if line.find('token:') >= 0:
                if self.verbose:
                    print "line is", line
                token = line.split('"')[1]
                if self.verbose:
                    print "token is", token
                if token:
                    return token
        raise("Unable to get a token")

    def fetchJson(self, token):
        '''Returns a json object after building the proper speed-test-url'''

        # https://api.fast.com/netflix/speedtest?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3
        # https://api.fast.com/netflix/speedtest?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3
        # lynx --dump  'https://api.fast.com/netflix/speedtest?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3'  | python -mjson.tool
        #url = 'https://api.fast.com/netflix/speedtest?https=true&token=YXNkZmFzZGxmbnNkYWZoYXNkZmhrYWxm&urlCount=3'
        # With the token, get the (3) speed-test-URLS from api.fast.com (which
        # will be in JSON format):

        baseurl = 'https://api.fast.com/'
        if self.forceipv4:  # Force IPv4 by manually resolving to a IPv4 address
            ipv4 = socket.getaddrinfo(
                'api.fast.com', 80, socket.AF_INET)[0][4][0]
            # HTTPS does not work IPv4 addresses, thus use HTTP ??
            baseurl = 'http://' + ipv4 + '/'
        elif self.forceipv6:  # ditto, but for ipv6
            ipv6 = socket.getaddrinfo(
                'api.fast.com', 80, socket.AF_INET6)[0][4][0]
            baseurl = 'http://[' + ipv6 + ']/'
        url = baseurl + 'netflix/speedtest?https=true&token=' + \
            token + '&urlCount=3'  # Not more than 3 possible
        if self.verbose:
            print "API url is", url
        try:
            urlresult = urllib2.urlopen(url, None, 2)  # 2 second time-out
        except:  # not good
            if self.verbose:
                print "No connection possible"  # probably IPv6, or just no network
            return 0  # no connection, thus no speed
        jsonresult = urlresult.read()
        return json.loads(jsonresult)

    def __runTest(self, json):
        '''Runs the actual tests - private due to random setup needed'''
        threads, results = ([], [])
        for elem in json:  # fill out speed test url from the json format
                # yeah, yeah, yeah, all sorts of not thread safe
            results.append(0)
            threads.append(Thread(target=threadThis, args=(
                elem['url'], results, len(threads))))
            threads[-1].daemon = True
            threads[-1].start()
        # wait for responses
        sleepSeconds, lasttotal, highestspeedkBps, maxdownloadMB, spds = (
            3.0, 0, 0, 60, [])
        for loop in range(int(self.maxtime / sleepSeconds)):
            time.sleep(sleepSeconds)
            # yeah, yeah, yeah, all sorts of not thread safe
            total = sum(results)
            delta = total - lasttotal
            spds.append((delta / sleepSeconds) / 1024.0)
            if self.verbose:
                print("Loop: {} Total MB: {} Delta MB: {} Speed (kbps): {}".format(
                    loop, total / (1024 * 1024), delta / (1024 * 1024), spds[-1]))
        # 8 for bits versus bytes /  1.0416 for application versus network
        # layerss
        x = max(spds) * 8 * 1.0415
        if self.verbose:
            print("Highest (Kbps): {}".format(x))
        return x

    def go(self):
        ''' go initialized the tests against fast.com '''
        token = self.fetchToken()
        json = self.fetchJson(token)
        return self.__runTest(json)

if __name__ == "__main__":
    print "let's speed test:"
    print "\nSpeed test, without logging:"
    f = fast()
    print(f.go())

    # print "\nSpeed test, with logging:"
    # print fast_com(verbose=True)
    # print "\nSpeed test, IPv4, with verbose logging:"
    # print fast_com(verbose=True, maxtime=18, forceipv4=True)
    # print "\nSpeed test, IPv6:"
    # print fast_com(maxtime=12, forceipv6=True)
    #fast_com(verbose=True, maxtime=25)

    print "\ndone"
