rule LY_WGKXwwwszleyucom
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 4D 79 46 75 6E 00 62 73 }

condition:
		$a0
}