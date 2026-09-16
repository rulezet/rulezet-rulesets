import "pe"
rule Upackv021BetaDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE 88 01 [2] AD 8B F8 [4] 33 }

condition:
		$a0 at pe.entry_point
}