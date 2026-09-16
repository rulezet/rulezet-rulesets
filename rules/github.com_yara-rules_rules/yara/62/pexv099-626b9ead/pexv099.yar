import "pe"
rule PEXv099
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 60 E8 01 [4] 83 C4 04 E8 01 [4] 5D 81 }

condition:
		$a0 at pe.entry_point
}