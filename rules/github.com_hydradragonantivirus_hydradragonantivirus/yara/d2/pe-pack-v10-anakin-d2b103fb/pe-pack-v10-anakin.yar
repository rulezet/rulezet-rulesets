import "pe"
rule _PE_Pack_v10__ANAKiN_
{
	meta:
		description = "PE Pack v1.0 -> ANAKiN"
	strings:
		$0 = {74 00 E9 ?? ?? ?? ?? 00 00 00 00}
	condition:
		$0 at pe.entry_point
}