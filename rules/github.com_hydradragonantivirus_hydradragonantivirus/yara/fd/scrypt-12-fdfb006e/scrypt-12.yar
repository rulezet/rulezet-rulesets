import "pe"
rule _Scrypt_12_
{
	meta:
		description = "Scrypt 1.2"
	strings:
		$0 = {BB 00 FE 00 1F 4B EB FB 26 46 FD CE 7E 0C CE 0A D5 D0 97 3B D2 89 EF 50 C0 B3 84 4E 8E CD CA 9D 63 B0 FE C3 5D 9C A3 98 A6 F0 8E 23 BA 71 D7 7E BC B5 B4 06 B2 3F 72 3B 76 D3 4F B1 AA CF 4B B5 A6 CB 6B A9 A6 A1 79 A0 C4 64 A2 A7 9A C6 99 52}
	condition:
		$0 at pe.entry_point
}