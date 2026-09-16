rule Upackv029Betav031BetaDwing
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE 88 01 [2] AD 8B F8 95 AD 91 F3 A5 AD B5 ?? F3 }

condition:
		$a0
}