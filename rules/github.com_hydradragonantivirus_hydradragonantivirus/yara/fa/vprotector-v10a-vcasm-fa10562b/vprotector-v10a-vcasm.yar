import "pe"
rule _VProtector_V10A__vcasm_
{
	meta:
		description = "VProtector V1.0A -> vcasm"
	strings:
		$0 = {55 8B EC 6A FF 68 8A 8E 40 00 68 C6 8E 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50}
	condition:
		$0 at pe.entry_point
}