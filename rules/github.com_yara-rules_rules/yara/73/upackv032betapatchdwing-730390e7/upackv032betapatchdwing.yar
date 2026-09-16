rule Upackv032BetaPatchDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE 88 01 [2] AD 50 ?? AD 91 F3 A5 }

condition:
		$a0
}