import "pe"
rule eXPressor11CGSoftLabs
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 [2] 00 00 E9 [2] 00 00 E9 ?? 12 00 00 E9 ?? 0C 00 00 E9 [2] 00 00 E9 [2] 00 00 E9 [2] 00 00 }

condition:
		$a0 at pe.entry_point
}