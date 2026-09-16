import "pe"
rule PENightMarev13
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 00 00 00 00 5D B9 [4] 80 31 15 41 81 F9 }

condition:
		$a0 at pe.entry_point
}