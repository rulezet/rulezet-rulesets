import "pe"
rule _ThemidaWinLicense_V2010_p_Hide_from_PE_scanners_Type2_
{
	meta:
		description = "Themida/WinLicense V2.0.1.0 + [Hide from PE scanners Type2"
	strings:
		$0 = {00 00 00 00 ?? ?? ?? ?? 00 00 00 00 6B 65 72 6E 65 6C 33 32 2E 64 6C 6C 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}