import "pe"
rule _ThinstallVS_v3104__Jitit_Software_
{
	meta:
		description = "Thinstall.VS v3.104 -> Jitit Software"
	strings:
		$0 = {9C 60 68 53 74 41 6C 68 54 68 49 6E E8 00 00 00 00 58 BB CC 1A 00 00 2B C3 50 68 00 00 ?? ?? 68 00 28 00 00 68 C8 00 00 00 E8 2C FF FF FF E9 90 FF FF FF CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA 00 00}
	condition:
		$0 at pe.entry_point
}