import "pe"
rule _PCPEC_alpha__preview_
{
	meta:
		description = "PCPEC alpha - preview"
	strings:
		$0 = {53 51 52 56 57 55 E8 00 00 00 00 5D 8B CD 81 ED 33 30 40 00}
	condition:
		$0 at pe.entry_point
}