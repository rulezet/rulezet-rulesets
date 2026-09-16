rule HyingsPEArmor075exeHyingCCG
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 00 00 00 00 00 00 00 00 [2] 00 00 00 00 00 00 [2] 01 00 00 00 00 00 00 00 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 00 00 [19] 00 00 00 00 00 00 00 00 00 74 [3] 00 00 00 00 00 }

condition:
		$a0
}