import "pe"
rule PEiDBundlev102v103DLLBoBBobSoft
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 7C 24 08 01 0F 85 [4] 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 41 00 08 00 39 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 }

condition:
		$a0 at pe.entry_point
}