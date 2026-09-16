import "pe"
rule _ASPack_v10804_
{
	meta:
		description = "ASPack v1.08.04"
	strings:
		$0 = {A8 03 61 75 08 B8 01 C2 0C 68 C3 8B 85 26 04 8D 8D 3B 04 51 50 FF}
	condition:
		$0 at pe.entry_point
}