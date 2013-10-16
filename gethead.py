#!/usr/bin python

#             _   _                    _ 
#            | | | |                  | |
#   __ _  ___| |_| |__   ___  __ _  __| |
#  / _` |/ _ \ __| '_ \ / _ \/ _` |/ _` |
# | (_| |  __/ |_| | | |  __/ (_| | (_| |
#  \__, |\___|\__|_| |_|\___|\__,_|\__,_|
#   __/ |                                
#  |___/                                 
#
# description:	http header vulnerability analysis project
# github:	https://github.com/httphacker
# email:	httphacker@icloud.com
# website:	http://httphacker.com
# twitter:	@httphacker
# version:	0.1

import sys
import urllib2

BLACK, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE = range(8)

def has_colours(stream):
    if not hasattr(stream, "isatty"):
        return False
    if not stream.isatty():
        return False
    try:
        import curses
        curses.setupterm()
        return curses.tigetnum("colors") > 2
    except:
        return False
has_colours = has_colours(sys.stdout)

def printout(text, colour=WHITE):
        if has_colours:
                seq = "\x1b[1;%dm" % (30+colour) + text + "\x1b[0m"
                sys.stdout.write(seq)
        else:
                sys.stdout.write(text)

if len(sys.argv) < 2:
  print
  printout('Please provide a fully-qualified path!\n', RED)
  printout('Usage: python gethead.py path\n', WHITE)
  printout('Example: python gethead.py http://www.google.com\n\n', WHITE)
  sys.exit()
else:
  response = urllib2.urlopen(sys.argv[1])
  print 
  printout('HTTP Header Analysis for ' + sys.argv[1] + ':' + '\n\n', CYAN)

# check x-xss-protection:
if response.info().getheader('x-xss-protection') == '1; mode=block':
  printout('(X-XSS-Protection) Cross-Site Scripting Protection is enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED) 
  printout('- Server does not enforce Cross-Site Scripting Protection.\nThe X-XSS-Protection Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting Attacks.\n\n', WHITE)

# check x-frame-options:
if response.info().getheader('x-frame-options') == 'deny' or 'sameorigin':
  printout('(X-Frame-Options) Cross-Frame Scripting Protection is enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce Cross-Frame Scripting Protection.\nThe X-Frame-Options Header setting is either inadequate or missing.\nClient may be vulnerable to Click-Jacking Attacks.\n\n', WHITE)

# check x-content-type-options:
if response.info().getheader('x-content-type-options') == 'nosniff':
  printout('(X-Content-Type-Options) MIME-Sniffing Protection is enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED) 
  printout('- Server does not enforce MIME-Sniffing Protection.\nThe X-Content-Type-Options Header setting is either inadequate or missing.\nClient may be vulnerable to MIME-Sniffing Attacks.\n\n', WHITE)

# check strict-transport-security:
if response.info().getheader('strict-transport-security'):
  printout('(Strict-Transport-Security) HTTP over TLS/SSL is enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce HTTP over TLS/SSL Connections.\nThe Strict-Transport-Security Header setting is either inadequate or missing.\nClient may be vulnerable to Session Information Leakage.\n\n', WHITE)

# check x-content-security-policy:
if response.info().getheader('x-content-security-policy'):
  printout('(X-Content-Security-Policy) Content Security Policy is enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a Content Security Policy.\nThe X-Content-Security-Policy Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting and Injection Attacks.\n\n', WHITE)

# check x-webkit-csp:
if response.info().getheader('x-webkit-csp'):
  printout('(X-WebKit-CSP) Content Security Policy is enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a Content Security Policy.\nThe X-WebKit-CSP Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Site Scripting and Injection Attacks.\n\n', WHITE)

# check access-control-allow-origin:
if response.info().getheader('access-control-allow-origin'):
  printout('(Access-Control-Allow-Origin) Access Control Policies are enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce an Access Control Policy.\nThe Access-Control-Allow-Origin Header setting is either inadequate or missing.\nClient may be vulnerable to Cross-Domain Scripting Attacks.\n\n', WHITE)

# check x-download-options:
if response.info().getheader('x-download-options') == 'noopen':
  printout('(X-Download-Options) File Download and Open Restriction Policies are enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a File Download and Open Policy.\nThe X-Download-Options Header setting is either inadequate or missing.\nClient may be vulnerable to Browser File Execution Attacks.\n\n', WHITE)

# check cache-control:
if response.info().getheader('cache-control'):
  printout('(Cache-control) Private Content Cacheing is enforced.\n\n', GREEN)
else:
  printout('Vulnerability ', RED)
  printout('- Server does not enforce a Content Cacheing Policy.\nThe Cache-control Header setting is either inadequate or missing.\nClient may be vulnerable to Content Caching Attacks.\n\n', WHITE)
