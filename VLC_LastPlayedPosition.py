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

VLC_LastPlayedPosition - WARNING: This program is provided "as-is"

Author    : Gabriele Zambelli (Twitter: @gazambelli)
Blog      : http://forensenellanebbia.blogspot.it
Version   : 20190127

Script to extract the last played position of the files opened with VLC media player
The script parses the following files:
Win   : C:/Users/<username>/AppData/Roaming/vlc/vlc-qt-interface.ini
Ubuntu: /home/<username>/.config/vlc/vlc-qt-interface.conf
macOS : /Users/<username>/Library/Preferences/org.videolan.vlc.plist

Requirements:
 - Python 2.7
 - biplist (pip install biplist)
   https://github.com/wooster/biplist

Scripted tested with:
 - VLC media player 3.0.5/3.0.6. Based on my tests, a zero value may either mean that the file has been fully played
   or that less than five percent of the file contents has been played.
'''

from datetime import datetime, timedelta
import biplist
import getpass
import os
import platform
import sys
import urllib

#functions
def get_help():
	print "\n Script to extract the last played position of the files opened with VLC media player"
	print "\n EXAMPLES:\n  Analyze VLC media player installed on this system:\n  - python VLC_LastPlayedPosition.py --default-path"
	print "\n  Analyze a specific file:"
	print "  - Win   : python VLC_LastPlayedPosition.py vlc-qt-interface.ini"
	print "  - Ubuntu: python VLC_LastPlayedPosition.py vlc-qt-interface.conf"
	print "  - macOS : python VLC_LastPlayedPosition.py org.videolan.vlc.plist"
	print "\n (All output goes to stdout and to a tab-delimited text file)"

def get_LPP_WinNix(vlc_path, fn):
	try:
		file = open(vlc_path, "r")
		print "\nAnalyzing file: %s..." % vlc_path
	except:
		print '\nThe following file was not found:\n%s\n' % vlc_path
		sys.exit()
	file = file.readlines()
	i = 0
	for line in file:
		if "RecentsMRL" in line:
			if "list=" in file[i + 1]:  # list= is one line after RecentsMRL
				vlc_list.append(file[i + 1].replace("list=", "").replace("\n", "").split(", "))
			if "times=" in file[i + 2]:  # times= is two lines after RecentsMRL
				vlc_times.append(file[i + 2].replace("times=", "").replace("\n", "").split(", "))
		i += 1
	if len(vlc_list) == 0:
		print "\nNo recent item found"
		sys.exit()
	print "\n%s" % ("-" * 42)
	print " VLC media player ('RecentsMRL' section)"
	print " The entries are listed by default from\n the most recent to the oldest"
	print "%s" % ("-" * 42)
	print "\n# | Last Played Position (h:mm:ss) | Media file"
	f = open(fn, "w")
	f.write("#\tMedia file\tLast Played Position (h:mm:ss)\tLast Played Position (raw value)\tVLC file\n")
	i = 0
	for item in vlc_list[0]:
		if len(item) > 1:
			fp = urllib.unquote(vlc_list[0][i]) # full path
			fp = fp.rstrip(",")
			raw_value = vlc_times[0][i]
			get_output(f, fp, raw_value, i, vlc_path)
		i += 1
	f.close()
	print "\nOutput saved to: %s" % fn

def get_LPP_macOS(vlc_path, fn):
	try:
		file = biplist.readPlist(vlc_path)
		print "\nAnalyzing file: %s..." % vlc_path
	except:
		print '\nThe following file was not found: %s\n' % vlc_path
		sys.exit()
	i = 0
	try:
		for key, val in file['recentlyPlayedMedia'].items():
			vlc_list.append(key)
			vlc_times.append(val)
	except:
		print "\nNo file was found under 'recentlyPlayedMedia' in the file.\n"
		sys.exit()
	if len(vlc_list) == 0:
		print "\nNo recent item found"
		sys.exit()
	print "\n%s" % ("-" * 49)
	print " VLC media player ('recentlyPlayedMedia' section)"
	print "%s" % ("-" * 49)
	print "\n# | Last Played Position (h:mm:ss) | Media file"
	f = open(fn, "w")
	f.write("#\tMedia file\tLast Played Position (h:mm:ss)\tLast Played Position (raw value)\tVLC file\n")
	i = 0
	for item in vlc_list:
		if len(item) > 1:
			fp = urllib.unquote(item) # full path
			fp = fp.rstrip(",")
			raw_value = vlc_times[i]
			get_output(f, fp, raw_value, i, vlc_path)
		i += 1
	f.close()
	print "\nOutput saved to: %s" % fn

def get_output(f, fp, raw_value, i, vlc_path):
	if vlc_path.endswith('.plist'):
		vlc_seconds = int(raw_value) # time value already in seconds
	else:
		raw_value   = raw_value.replace(",", "")
		vlc_seconds = (int(raw_value) / 1000)  # time value is in milliseconds
	if int(raw_value) > 0:
		lpp = timedelta(seconds=vlc_seconds)  # last played position
		print "%d | %s | %s" % (i + 1, lpp, fp)
		f.write("%d\t%s\t%s\t%s\t%s\n" % (i + 1, fp, lpp, raw_value, vlc_path))
	else:
		print "%d |   N/A   | %s" % (i + 1, fp)
		f.write("%d\t%s\tN/A\t%s\t%s\n" % (i + 1, fp, raw_value, vlc_path))

#start
s_time = datetime.now()  # script starting time
p_time = s_time.strftime('%Y%m%d_%H%M%S')  # prefix time
fn     = p_time + "_vlc.csv"  # output file
myOS      = platform.system()
username  = getpass.getuser()
vlc_list  = []
vlc_times = []
if len(sys.argv) == 2:
	if sys.argv[1] == '--default-path':
		if myOS == 'Windows':
			vlc_path = 'C:/Users/' + username + '/AppData/Roaming/vlc/vlc-qt-interface.ini'
			get_LPP_WinNix(vlc_path, fn)
		if myOS == 'Linux':
			vlc_path = '/home/' + username + '/.config/vlc/vlc-qt-interface.conf'
			get_LPP_WinNix(vlc_path, fn)
		if myOS == 'Darwin':
			vlc_path = '/Users/' + username + '/Library/Preferences/org.videolan.vlc.plist'
			get_LPP_macOS(vlc_path, fn)
	elif 'vlc-qt-interface' in sys.argv[1]:
		vlc_path = os.path.abspath(sys.argv[1])
		get_LPP_WinNix(vlc_path, fn)
	elif 'org.videolan.vlc.plist' in sys.argv[1]:
		vlc_path = os.path.abspath(sys.argv[1])
		get_LPP_macOS(vlc_path, fn)
	else:
		get_help()
else:
	get_help()