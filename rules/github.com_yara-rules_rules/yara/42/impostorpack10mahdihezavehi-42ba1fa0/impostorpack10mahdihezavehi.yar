import "pe"
rule IMPostorPack10MahdiHezavehi
{
      meta:
		author="malware-lu"
strings:
		$a0 = { BE [3] 00 83 C6 01 FF E6 00 00 00 00 [2] 00 00 00 00 00 00 00 00 00 [3] 00 ?? 02 [2] 00 10 00 00 00 02 00 }

condition:
		$a0 at pe.entry_point
}