import "pe"
rule CrypKeyV56XKenonicControlsLtd
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E8 [4] E8 [4] 83 F8 00 75 07 6A 00 E8 }

condition:
		$a0 at pe.entry_point
}