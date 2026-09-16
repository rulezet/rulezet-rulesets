import "pe"
rule _PESpin_03__cyberbob_
{
	meta:
		description = "PESpin 0.3 -> cyberbob"
	strings:
		$0 = {EB 01 68 60 E8 00 00 00 00 8B 1C 24 83 C3 12 81 2B E8 B1 06 00 FE 4B}
	condition:
		$0 at pe.entry_point
}