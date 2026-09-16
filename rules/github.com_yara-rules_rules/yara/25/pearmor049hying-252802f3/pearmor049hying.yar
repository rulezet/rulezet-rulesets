import "pe"
rule PEArmor049Hying
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 56 52 51 53 55 E8 15 01 00 00 32 [2] 00 00 00 00 00 }

condition:
		$a0 at pe.entry_point
}