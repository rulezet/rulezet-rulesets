import "pe"
rule _Code_Virtualizer_V1310__Oreans_Technologies_
{
	meta:
		description = "Code Virtualizer V1.3.1.0 -> Oreans Technologies"
	strings:
		$0 = {60 9C FC E8 00 00 00 00 5F 81 EF ?? ?? ?? ?? 8B C7 81 C7 ?? ?? ?? ?? 3B 47 2C 75 02 EB 2E 89 47 2C B9 A7 00 00 00 EB 05 01 44 8F ?? 49 0B C9 75 F7 83 7F 40 00 74 15 8B 77 40 03 F0 EB 09 8B 1E 03 D8 01 03 83 C6 04 83 3E 00 75 F2 8B 74 24 24 8B DE 03 F0 B9}
	condition:
		$0 at pe.entry_point
}