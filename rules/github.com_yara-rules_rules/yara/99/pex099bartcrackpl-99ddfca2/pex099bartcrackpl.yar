import "pe"
rule PeX099bartCrackPl
{
      meta:
		author="malware-lu"
strings:
		$a0 = { E9 F5 [3] 0D 0A C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 C4 }

condition:
		$a0 at pe.entry_point
}