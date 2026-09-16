import "pe"
rule Kryptonv04
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 54 E8 [4] 5D 8B C5 81 ED 61 34 [2] 2B 85 60 37 [2] 83 E8 06 }

condition:
		$a0 at pe.entry_point
}