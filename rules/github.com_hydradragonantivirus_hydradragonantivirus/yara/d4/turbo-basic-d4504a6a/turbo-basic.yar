import "pe"
rule _Turbo_Basic_
{
	meta:
		description = "Turbo Basic"
	strings:
		$0 = {2E 8C 1E B2 00 2E C7 06 AE 00 00 00 E8 54 05 E8 88 00 E8 17 17 E8 AE 17 E8 11 00 2E 8E 1E 64 01 FF 36 02 00 E8 9F 17 58 B4 4C CD 21 E8 A7 00 E8 D6 00 72 53 E8 C4 01 E8 48 02 E8 6C 02 E8 00 1F E8 00 2F E8 52 01 0E 1F A1 56 01 B1 04 D3 E0 A3}
	condition:
		$0 at pe.entry_point
}