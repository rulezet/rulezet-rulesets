import "pe"
rule PureBasicDLLNeilHodgson
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 83 7C 24 08 01 75 ?? 8B 44 24 04 A3 [3] 10 E8 }

condition:
		$a0 at pe.entry_point
}