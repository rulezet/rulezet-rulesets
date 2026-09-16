import "pe"
rule StonesPEEncruptorv113
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 55 57 56 52 51 53 E8 [4] 5D 8B D5 81 }

condition:
		$a0 at pe.entry_point
}