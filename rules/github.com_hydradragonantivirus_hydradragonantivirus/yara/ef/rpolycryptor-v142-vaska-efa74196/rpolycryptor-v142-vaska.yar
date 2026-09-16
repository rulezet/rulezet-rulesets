import "pe"
rule _RPolyCryptor_V142__Vaska_
{
	meta:
		description = "RPolyCryptor V1.4.2 -> Vaska"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 00 00}
	condition:
		$0 at pe.entry_point
}