import "pe"
rule tElockv098tE
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 25 E4 FF FF 00 00 00 [8] 00 00 00 00 00 00 00 00 [12] 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [4] 00 00 00 00 [4] 00 }

condition:
		$a0 at pe.entry_point
}