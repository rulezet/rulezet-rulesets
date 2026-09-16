import "pe"
rule _Ciphator_46_
{
	meta:
		description = "Ciphator 4.6"
	strings:
		$0 = {93 93 E8 E4 0C 54 4C 4F 53 53 20 65 72 72 6F 72 05 23 00 00 00 00 00 00 8C C0 2E 31 06 18 0D B8 00 0D CD 21 33 C0 8E D8 66 0F B7 C8 0E 8F 06 06 00 68 DF 0C 8F 06 04 00 8C C8 8E D8 8E C0 B9 44 06 BE D8 0C 8B FE 2E 8B 16 14 00 FD CD 01 E2 FC}
	condition:
		$0 at pe.entry_point
}