import "pe"
rule _HackStop_115__117_EXE_
{
	meta:
		description = "HackStop 1.15 - 1.17 [EXE]"
	strings:
		$0 = {E8 00 00 52 BA EB 04 5A EB FB 9A B0 AD E6 64 52 BA EB 04 5A EB FB 9A 1E 52 B8 4D 30 CD 21 86 C4 3D FE 02 73 02 CD 20 52 BA EB 04 5A EB FB 9A 0E 1F E8 02 00 24 24 5A B4 09 CD 21 52 BA EB 04 5A EB FB 9A EB 02 D8 88 5A 1F 52 BA EB 04 5A EB FB}
	condition:
		$0 at pe.entry_point
}