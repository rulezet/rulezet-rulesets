import "pe"
rule _TPack_05m2_
{
	meta:
		description = "TPack 0.5?-m2"
	strings:
		$0 = {68 00 01 FD 60 BE 00 00 BF 48 FF B9 00 00 F3 A4 8B F7 BF 00 01 FC 46 E9 CE FD}
	condition:
		$0 at pe.entry_point
}