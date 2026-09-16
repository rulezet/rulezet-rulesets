import "pe"
rule VxNecropolis
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 50 FC AD 33 C2 AB 8B D0 E2 F8 }

condition:
		$a0 at pe.entry_point
}