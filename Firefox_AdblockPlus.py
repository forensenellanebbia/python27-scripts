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

Firefox_AdblockPlus - WARNING: This program is provided "as-is"

Author    : Gabriele Zambelli (Twitter: @gazambelli)
Blog      : http://forensenellanebbia.blogspot.it
Version   : 20190122

The script parses the 'storage.js' file used by Adblock Plus for Firefox and extracts the websites that have been whitelisted by the user.

Firefox - Adblock Plus addon: https://addons.mozilla.org/en-US/firefox/addon/adblock-plus/
Firefox - file location:
 - Win: C:\Users\<username>\AppData\Roaming\Mozilla\Firefox\Profiles\<profileID>.default\browser-extension-data\{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}\storage.js
 - Ubuntu: /home/<username>/.mozilla/firefox/<profileID>.default/browser-extension-data/{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}/storage.js
 - macOS: /Users/<username>/Library/Application Support/Firefox/Profiles/<profileID>.default/browser-extension-data/{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}/storage.js

The script doesn't support yet Chrome since this browser uses LevelDBs instead of 'storage.js'.
Adblock Plus: https://chrome.google.com/webstore/detail/adblock-plus/cfhdojbkjhnklbpkdaibdccddilifddb
Chrome: C:\Users\<username>\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\cfhdojbkjhnklbpkdaibdccddilifddb\[0-9]{6}.ldb

 The script was tested with:
 - Python 2.7
 - Firefox v64.0.2
 - Adblock Plus v3.4.2
'''

import getpass
import os
import platform
import re
import sys

#Functions
def get_help():
    print '\nAnalysis of Adblock Plus for Firefox:\nscript to extract whitelisted websites added by user'
    print '\nExamples'
    print '  Analyze the Firefox profile path on the current system\n  python Firefox_AdblockPlus.py --default-path'
    print '\n  Analyze a specific storage.js file\n  python Firefox_AdblockPlus.py storage.js'

def get_whitelisted(StorageJS):
    match = re.search('"\[Subscription\]","url=~user~\d*","defaults=whitelist","","\[Subscription filters\]",',
                      StorageJS)
    try:
        match_start = match.start()
    except:
        match_start = 0
    if match_start > 0:
        TextSelection = []
        for char in range(match_start, len(StorageJS), 1):
            TextSelection.append(StorageJS[char])
        TextSelection = ''.join(TextSelection)
        temp_list     = TextSelection.split(',')
        whitelisted   = []
        for item in temp_list:
            if '@@||' in item:
                if '^$document' in item:
                    item = item.replace('@@||', '').replace('^$document', '')
                    item = item.replace('"', '').replace('[', '').replace(']', '')
                    whitelisted.append(item)
        print '\nWhitelisted websites added by user: %d' % len(whitelisted)
        for website in sorted(whitelisted):
            print '- ' + website
    else:
        print '\nWhitelisted websites added by user: 0'

#Start
if len(sys.argv) == 2:
    if sys.argv[1] == '--default-path':
        myOS        = platform.system()
        username    = getpass.getuser()
        if myOS == 'Windows':
            firefox_profile = 'C:/Users/' + username + '/AppData/Roaming/Mozilla/Firefox/Profiles'
        if myOS == 'Linux':
            firefox_profile = '/home/' + username + '/.mozilla/firefox'
        if myOS == 'Darwin':
            firefox_profile = '/Users/' + username + '/Library/Application Support/Firefox/Profiles'
        try:
            firefox_dirs = os.listdir(firefox_profile)
            for firefox_dir in firefox_dirs:
                if '.default' in firefox_dir:
                    firefox_profile  = firefox_profile + '/' + firefox_dir + '/browser-extension-data/{d10d0bf8-f5b5-c8b4-a8b2-2b9879e08c5d}/storage.js'
            StorageJS = open(firefox_profile, "r")
            StorageJS = StorageJS.read()
            print '\n# Analysis of Adblock Plus for Firefox #'
            print 'File: %s' % firefox_profile
            get_whitelisted(StorageJS)
        except:
            print '\nError - The following file was not found:\n%s' % firefox_profile
    elif 'storage.js' in sys.argv[1].lower():
        StorageJS = open(sys.argv[1], "r")
        StorageJS = StorageJS.read()
        print '\n# Analysis of Adblock Plus for Firefox #'
        print 'File: %s' % os.path.abspath(sys.argv[1])
        get_whitelisted(StorageJS)
    else:
        get_help()
else:
    get_help()