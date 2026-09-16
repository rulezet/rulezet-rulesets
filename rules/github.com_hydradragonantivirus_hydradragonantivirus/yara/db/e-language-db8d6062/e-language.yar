import "pe"
rule _E_language_
{
	meta:
		description = "E language"
	strings:
		$0 = {E8 06 00 00 00 50 E8 ?? 01 00 00 55 8B EC 81 C4 F0 FE FF FF}
	condition:
		$0 at pe.entry_point
}