import "pe"
rule VxVirusConstructorIVPbased
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 [2] E8 [2] 5D [5] 81 ED [6] E8 [2] 81 FC [4] 8D [3] BF [2] 57 A4 A5 }

condition:
		$a0 at pe.entry_point
}