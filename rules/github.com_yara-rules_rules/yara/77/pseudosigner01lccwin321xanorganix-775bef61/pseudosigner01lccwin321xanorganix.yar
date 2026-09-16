import "pe"
rule PseudoSigner01LCCWin321xAnorganix
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 64 A1 01 00 00 00 55 89 E5 6A FF 68 [4] 68 9A 10 40 90 50 E9 }

condition:
		$a0 at pe.entry_point
}