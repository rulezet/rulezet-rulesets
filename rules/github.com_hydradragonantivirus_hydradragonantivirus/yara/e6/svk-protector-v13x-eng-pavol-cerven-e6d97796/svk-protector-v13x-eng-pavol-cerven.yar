import "pe"
rule _SVK_Protector_v13x_Eng__Pavol_Cerven_
{
	meta:
		description = "SVK Protector v1.3x (Eng) -> Pavol Cerven"
	strings:
		$0 = {60 E8 00 00 00 00 5D 81 ED 06 00 00 00 EB 05 B8 ?? ?? 42 00 64 A0 23 00 00 00 EB 03 C7 84 E8 84 C0 EB 03 C7 84 E9 75 67 B9 49 00 00 00 8D B5 C5 02 00 00 56 80 06 44 46 E2 FA 8B 8D C1 02 00 00 5E 55 51 6A 00 56 FF 95 0C 61 00 00 59 5D 40 85 C0 75 3C 80 3E}
	condition:
		$0 at pe.entry_point
}