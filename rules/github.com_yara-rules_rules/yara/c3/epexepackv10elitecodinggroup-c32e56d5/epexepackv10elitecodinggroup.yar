import "pe"
rule EPExEPackV10EliteCodingGroup
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 68 [4] B8 [4] FF 10 }

condition:
		$a0 at pe.entry_point
}