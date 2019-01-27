'''
*********************************** LICENSE ***********************************
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You can view the GNU General Public License at <http://www.gnu.org/licenses/>
*******************************************************************************
WARNING: This program is provided "as-is"

Script name: Firefox_NoScript
Author     : Gabriele Zambelli (Twitter: @gazambelli)
Blog       : https://forensenellanebbia.blogspot.it
Version    : 20190127

This script parses the 'storage-sync.sqlite' file and extracts the permissions that have been manually added to NoScript add-on.
The file is located at:
Windows: C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profileID>.default\storage-sync.sqlite
         C:\Users\<username>\Desktop\Tor Browser\Browser\TorBrowser\Data\Browser\profile.default\storage-sync.sqlite
Ubuntu : /home/<username>/.mozilla/firefox/<profileID>.default/storage-sync.sqlite
macOS  : /Users/<username>/Library/Application Support/Firefox/Profiles/<profileID>.default/storage-sync.sqlite

The script was tested with:
- Python 2.7
- Firefox v64.0.2
- NoScript v10.2.1
'''

from collections import Counter
from datetime import datetime
import getpass
import json
import os
import platform
import re
import sqlite3
import ssl
import sys
import urllib2

#functions
def get_help():
    print "\nScript to extract the permissions that have been manually added to NoScript add-on"
    print "\nOPTIONS:"
    print "--default-path: Find and analyze the storage-sync.sqlite file in the Firefox profile path on the current system" #]\n==> python Firefox_NoScript.py --default-path"
    print "-r: Send a HTTP request to the sites found in the storage-sync.sqlite file to try to determine which of them may have been directly visited by the user"
    print "\nEXAMPLES:"
    print "python Firefox_NoScript.py --default-path [-r]"
    print "python Firefox_NoScript.py storage-sync.sqlite [-r]"

def get_version():
    script_name    = "Firefox_NoScript"
    script_version = "20190127"
    script_descr   = "Script to extract the permissions that have been manually added to NoScript add-on"
    print "\n%s v.%s\n%s" % (script_name,script_version,script_descr)

def get_sites(StorageSyncDB):
    connect = sqlite3.connect(StorageSyncDB)
    cursor  = connect.cursor()
    cursor.execute(
        "SELECT record FROM collection_data WHERE collection_name = 'default/{73a6fe31-595d-460b-a920-fcc0f8843232}' AND record_id = 'key-policy'")
    record = str(cursor.fetchall())
    connect.close()
    record = record.replace("[(u'", "").replace("',)]", "").replace("\\xa7:", "")
    sites  = json.loads(record)
    get_version()
    print '\nAnalyzing file: %s ...' % StorageSyncDB
    sites_trusted   = sites['data']['sites']['trusted']
    sites_untrusted = sites['data']['sites']['untrusted']
    sites_merged      = {}
    if len(sites_trusted) > 0:
        for site in sites_trusted:
            if site not in sites_trusted_default:
                sites_merged[site] = "trusted"
    if len(sites_untrusted) > 0:
        for site in sites_untrusted:
            sites_merged[site] = "untrusted"
    get_visited(sites_merged)


def get_visited(sites):
    if len(sites) == 0:
        print '\n** NoScript TRUSTED sites **\n   Non-default permissions found: (%d)' % Counter(sites.values())["trusted"]
        print '\n** NoScript UNTRUSTED sites **\n   Non-default permissions found: (%d)' % Counter(sites.values())["untrusted"]
    else:
        sites_visited_n = []
        sites_visited_y = []
        http_responses  = {} #dictionary to store HTTP responses

        if len(sys.argv) == 3:
            if "-r" in sys.argv:
                if os.path.isfile(fn) == False:
                    f = open(fn, "w")
                    f.write("Site,TrustLevel,Visited,HttpResponse,Content-Length,ResponseURL,File\n")
                else:
                    f = open(fn, "a")
                print "\nNon-default permissions found: (%d)" % len(sites)
                print "\nSending HTTP requests to %d domains found in the file..." % len(sites)
                for site,trust_level in sites.items():
                    if '.onion' in site:
                        sites_visited_y.append(site)
                        f.write("%s,%s,possible,,,,%s\n" % (site,trust_level,StorageSyncDB))
                    else:
                        try:
                            url     = "http://" + site.rstrip()
                            hdr     = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:64.0) Gecko/20100101 Firefox/64.0'}
                            req     = urllib2.Request(url)
                            context = ssl._create_unverified_context() #avoid "SSL: CERTIFICATE_VERIFY_FAILED" error
                            try:
                                res = urllib2.urlopen(req, timeout=3, context=context)
                                res_url = res.url
                                http_responses[site]=res.read()
                            except:
                                try:
                                    req = urllib2.Request(url, headers=hdr)
                                    res = urllib2.urlopen(req, timeout=3, context=context)
                                    res_url = res.url
                                    http_responses[site] = res.read()
                                except:
                                    res_url = ""
                                    pass
                            if site in res_url: #if not, res.url is a redirect
                                header = res.info().headers
                                content_length = [header.index(i) for i in header if 'Content-Length' in i]
                                if len(content_length) == 0: #the Content-Length field is missing
                                    sites_visited_y.append(site)
                                    f.write("%s,%s,possible,yes,,%s,%s\n" % (site,trust_level,res_url,StorageSyncDB))
                                else:
                                    content_length = content_length[0]
                                    content_length = header[content_length]
                                    content_length = int(content_length.replace("Content-Length: ", "").rstrip())
                                    if content_length < 1024: #"not visited" if Content-Length is less than 1024 bytes
                                        sites_visited_n.append(site)
                                        f.write("%s,%s,,yes,%d,%s,%s\n" % (site,trust_level,content_length,res_url,StorageSyncDB))
                                    else:
                                        sites_visited_y.append(site)
                                        f.write("%s,%s,possible,yes,%d,%s,%s\n" % (site,trust_level,content_length,res_url,StorageSyncDB))
                            else:
                                sites_visited_n.append(site)
                                f.write("%s,%s,,yes,,%s,%s\n" % (site,trust_level,res_url,StorageSyncDB))
                        except:
                            sites_visited_n.append(site)
                            f.write("%s,%s,,no,,,,%s\n" % (site,trust_level,StorageSyncDB))
                f.close()
                sites_script = []
                for domain in sites_visited_y:
                    for keys, values in http_responses.items():
                        #search lines in HTML source code that load scripts
                        regexp_list = ['<(script|iframe|wsc)?[ \.]?(type="text/javascript"|type=\'text/javascript\'|async)?[ \.\r\n]*src[a-zA-Z0-9="\'\\\./:%_-]*' + domain,
                                       '<link rel=["|\']+(preload|prefetch|preconnect|dns-prefetch)+[a-zA-Z0-9\.="-:/ ]*' + domain]
                        for regexp in regexp_list:
                            m = re.search(regexp, values)
                            if m:
                                if keys != domain:
                                    sites_script.append(domain)
                sites_script    = sorted(set(sites_script))
                sites_visited_n = sorted(set(sites_visited_n))
                sites_visited_y = sorted(set(sites_visited_y))

                if len(sites_script) > 0:
                    for site_script in sites_script:
                        sites_visited_n.append(site_script)
                        sites_visited_y.remove(site_script)

                    f_in      = open(fn,"r")
                    f_in_rows = []
                    for line in f_in:
                        f_in_rows.append(line)
                    f_in.close()

                    f_out_rows = list(f_in_rows) #clone f_in_rows
                    for f_in_row in f_in_rows:
                        for site_script in sites_script:
                            if f_in_row.startswith(site_script):
                                f_in_newrow = f_in_row.replace("possible","")
                                f_out_rows.remove(f_in_row)
                                f_out_rows.append(f_in_newrow)
                    fnt   = "temp.csv"
                    f_out = open(fnt,"w")
                    for f_out_row in f_out_rows:
                        f_out.write(f_out_row)
                    f_out.close()

                    os.remove(fn)
                    os.rename(fnt,fn)

                print "\n   Based on the HTTP responses received, it's possible that:"
                print "     ==> the user directly visited %d domain(s): " % len(sites_visited_y)
                if len(sites_visited_y) > 0:
                    for site_visited_y in sorted(sites_visited_y):
                        print "      - " + site_visited_y
                print "\n     ==> the trust level for %d domain(s) was set by the user\n     when visiting other domains:" % len(sites_visited_n)
                if len(sites_visited_n) > 0:
                    for site_visited_n in sorted(sites_visited_n):
                        print "      - " + site_visited_n
                print "\nOutput saved to: %s" % fn

        else:
            print '\n** NoScript TRUSTED sites **\n   Non-default permissions found: (%d)' % Counter(sites.values())["trusted"]
            if Counter(sites.values())["trusted"]:
                for site, trust_level in sorted(sites.items()):
                    if trust_level == "trusted":
                        print "   - " + site
            print '\n** NoScript UNTRUSTED sites **\n   Non-default permissions found: (%d)' % Counter(sites.values())["untrusted"]
            if Counter(sites.values())["untrusted"] > 0:
                for site,trust_level in sorted(sites.items()):
                    if trust_level == "untrusted":
                        print "   - " + site


#start
# From NoScript v10.2.1: default list of trusted sites
# (From NoScript v10.2.1: default list of untrusted sites is empty)
sites_trusted_default = "addons.mozilla.org", "afx.ms", "ajax.aspnetcdn.com", "ajax.googleapis.com", "bootstrapcdn.com", "code.jquery.com", "firstdata.com", "firstdata.lv", "gfx.ms", "google.com", "googlevideo.com", "gstatic.com", "hotmail.com", "live.com", "live.net", "maps.googleapis.com", "mozilla.net", "netflix.com", "nflxext.com", "nflximg.com", "nflxvideo.net", "noscript.net", "outlook.com", "passport.com", "passport.net", "passportimages.com", "paypal.com", "paypalobjects.com", "securecode.com", "securesuite.net", "sfx.ms", "tinymce.cachefly.net", "wlxrs.com", "yahoo.com", "yahooapis.com", "yimg.com", "youtube.com", "ytimg.com"

if len(sys.argv) > 1:
    s_time = datetime.now()  # script starting time
    p_time = s_time.strftime('%Y%m%d_%H%M%S')  # prefix time
    fn     = p_time + "_NoScript.csv"  # output file
    if '--default-path' in sys.argv:
        myOS     = platform.system()
        username = getpass.getuser()
        if myOS == 'Windows':
            firefox_profile = 'C:/Users/' + username + '/AppData/Roaming/Mozilla/Firefox/Profiles'
        if myOS == 'Linux':
            firefox_profile = '/home/' + username + '/.mozilla/firefox'
        if myOS == 'Darwin':
            firefox_profile = '/Users/' + username + '/Library/Application Support/Firefox/Profiles'
        try:
            firefox_dirs = os.listdir(firefox_profile)
        except:
            print "The following path %s was not found.\n" % firefox_profile
            sys.exit()
        try:
            for firefox_dir in firefox_dirs:
                if '.default' in firefox_dir:
                    StorageSyncDB = firefox_profile + '/' + firefox_dir + '/storage-sync.sqlite'
                    get_sites(StorageSyncDB)
        except:
            print '\nError - The following file was not found:\n%s\n' % StorageSyncDB
    elif 'storage-sync.sqlite' in str(sys.argv):
        for arg in sys.argv:
            if 'storage-sync.sqlite' in arg:
                StorageSyncDB = os.path.abspath(arg)
                get_sites(StorageSyncDB)
    else:
        get_help()
else:
    get_help()

