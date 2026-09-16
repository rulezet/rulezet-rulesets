import "pe"
rule DJoinv07publicxorencryptiondrmist
{
      meta:
		author="malware-lu"
strings:
		$a0 = { C6 05 [2] 40 00 00 [8] 00 [4] 00 [5] 00 }

condition:
		$a0 at pe.entry_point
}