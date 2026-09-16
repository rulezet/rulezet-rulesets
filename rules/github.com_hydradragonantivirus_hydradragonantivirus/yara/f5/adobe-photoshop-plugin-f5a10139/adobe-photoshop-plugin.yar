import "pe"
rule _Adobe_PhotoShop_Plugin_
{
	meta:
		description = "Adobe PhotoShop Plugin"
	strings:
		$0 = {83 7C 24 08 01 75 09 8B 44 24 04 A3 00 00 00 10 B8 01 00 00 00 C2 0C 00 8D 64 24 00 8D 64 24 00 56 57 8B 74 24 0C 8B 7E 0C 83 C7 0C 83 3F}
	condition:
		$0 at pe.entry_point
}