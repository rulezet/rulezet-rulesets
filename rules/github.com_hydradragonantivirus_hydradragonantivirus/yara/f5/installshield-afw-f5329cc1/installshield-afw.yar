import "pe"
rule _InstallShield_AFW_
{
	meta:
		description = "InstallShield AFW"
	strings:
		$0 = {55 8B EC 6A FF 68 18 33 41 00 68 80 BA 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 53 56 57 89 65 E8 FF 15 E8 31 41 00 33 D2 8A D4 89 15 5C 63 41 00 8B C8 81 E1 FF 00 00 00 89 0D 58 63 41 00 C1 E1 08 03 CA 89 0D 54 63 41 00 C1 E8 10 A3 50 63 41 00 33 F6 56 E8 E0 00 00 00 59 85 C0 75 08}
	condition:
		$0 at pe.entry_point
}