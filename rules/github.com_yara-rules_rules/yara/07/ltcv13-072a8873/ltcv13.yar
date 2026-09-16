import "pe"
rule LTCv13
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 54 E8 00 00 00 00 5D 8B C5 81 ED F6 73 40 00 2B 85 87 75 40 00 83 E8 06 }

condition:
		$a0 at pe.entry_point
}