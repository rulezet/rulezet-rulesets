import "pe"
rule _PEPACK_10_
{
	meta:
		description = "PE-PACK 1.0"
	strings:
		$0 = {50 FC AD 33 C2 AB 8B D0 E2 F8}
		$1 = {74 00 E9}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}