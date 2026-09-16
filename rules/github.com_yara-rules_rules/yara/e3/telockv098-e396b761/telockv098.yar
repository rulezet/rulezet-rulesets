import "pe"
rule tElockv098
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 [4] 1E }

condition:
		$a0 at pe.entry_point
}