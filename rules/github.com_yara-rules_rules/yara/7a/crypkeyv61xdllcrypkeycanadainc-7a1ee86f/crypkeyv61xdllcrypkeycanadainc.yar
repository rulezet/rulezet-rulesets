import "pe"
rule CrypKeyV61XDLLCrypKeyCanadaInc
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 3D [4] 00 75 34 68 [4] E8 }

condition:
		$a0 at pe.entry_point
}