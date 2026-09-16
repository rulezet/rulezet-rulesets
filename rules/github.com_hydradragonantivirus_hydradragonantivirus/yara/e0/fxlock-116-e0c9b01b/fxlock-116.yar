import "pe"
rule _FXlock_116_
{
	meta:
		description = "F-Xlock 1.16"
	strings:
		$0 = {50 50 50 53 51 52 56 1E 8B DC 8C D8 05 00 00 36 89 47 0E 36 C7 47 0C 00 00 8E 1E 2C 00 33 DB 8B 07 43 3D 00 00 74 02 75 F6 43 83 3F 01 75 45 43 43 8B D3 B8 00 3D CD 21 72 3A 8B D8 0E 1F 33 D2 8B F2 B9 1B 00 B4 3F CD 21 83 7C 14 00 75 30 81}
	condition:
		$0 at pe.entry_point
}