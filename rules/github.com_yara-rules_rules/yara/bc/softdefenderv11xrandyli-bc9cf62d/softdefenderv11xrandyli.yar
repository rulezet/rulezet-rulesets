import "pe"
rule SoftDefenderV11xRandyLi
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 74 07 75 05 19 32 67 E8 E8 74 1F 75 1D E8 68 39 44 }

condition:
		$a0 at pe.entry_point
}