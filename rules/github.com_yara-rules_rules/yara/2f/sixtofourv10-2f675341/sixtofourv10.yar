import "pe"
rule SixtoFourv10
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 50 55 4C 50 83 [2] FC BF [2] BE [2] B5 ?? 57 F3 A5 C3 33 ED }

condition:
		$a0 at pe.entry_point
}