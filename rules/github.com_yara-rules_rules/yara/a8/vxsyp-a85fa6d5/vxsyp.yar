import "pe"
rule VxSYP
{
      meta:
		author="malware-lu"
strings:
		$a0 = { 47 8B C2 05 1E 00 52 8B D0 B8 02 3D CD 21 8B D8 5A }

condition:
		$a0 at pe.entry_point
}