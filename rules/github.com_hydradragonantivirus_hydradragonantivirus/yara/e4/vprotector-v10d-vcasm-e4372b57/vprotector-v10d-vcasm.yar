import "pe"
rule _VProtector_V10D__vcasm_
{
	meta:
		description = "VProtector V1.0D -> vcasm"
	strings:
		$0 = {55 8B EC 6A FF 68 CA 31 41 00 68 06 32 41 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50}
	condition:
		$0 at pe.entry_point
}