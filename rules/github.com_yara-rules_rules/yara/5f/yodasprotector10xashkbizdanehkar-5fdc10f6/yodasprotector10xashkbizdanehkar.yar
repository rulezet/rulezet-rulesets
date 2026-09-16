import "pe"
rule yodasProtector10xAshkbizDanehkar
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 8B EC 53 56 57 E8 03 00 00 00 EB 01 }

condition:
		$a0 at pe.entry_point
}