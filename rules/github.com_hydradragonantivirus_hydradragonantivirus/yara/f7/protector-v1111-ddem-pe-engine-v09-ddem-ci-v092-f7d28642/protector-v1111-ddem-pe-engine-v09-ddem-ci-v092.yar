import "pe"
rule __Protector_v1111_DDeM__PE_Engine_v09_DDeM__CI_v092_
{
	meta:
		description = "*** Protector v1.1.11 (DDeM -> PE Engine v0.9, DDeM -> CI v0.9.2)"
	strings:
		$0 = {53 51 56 E8 00 00 00 00 5B 81 EB 08 10 00 00 8D B3 34 10 00 00 B9 F3 03 00 00 BA 63 17 2A EE 31 16 83 C6 04}
	condition:
		$0 at pe.entry_point
}