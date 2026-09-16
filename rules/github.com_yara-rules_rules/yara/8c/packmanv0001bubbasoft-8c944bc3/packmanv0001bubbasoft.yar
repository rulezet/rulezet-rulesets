import "pe"
rule PackmanV0001Bubbasoft
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 00 00 00 00 58 8D [5] 8D [5] 8D [5] 8D [2] 48 }

condition:
		$a0 at pe.entry_point
}