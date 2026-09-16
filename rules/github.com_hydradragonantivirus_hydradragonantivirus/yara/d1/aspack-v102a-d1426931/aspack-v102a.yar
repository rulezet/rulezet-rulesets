import "pe"
rule _ASPack_v102a_
{
	meta:
		description = "ASPack v1.02a"
	strings:
		$0 = {60 E8 5D 81 ED 96 78 43 B8 90 78 43 03 C5 2B 85 7D 7C 43 89 85 89 7C 43 80 BD 74 7C}
	condition:
		$0 at pe.entry_point
}