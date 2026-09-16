rule Upackv032BetaDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE 88 01 [2] AD 50 [2] AD 91 F3 A5 }
	$a1 = { BE 88 01 [2] AD 50 ?? AD 91 ?? F3 A5 }

condition:
		$a0 or $a1
}