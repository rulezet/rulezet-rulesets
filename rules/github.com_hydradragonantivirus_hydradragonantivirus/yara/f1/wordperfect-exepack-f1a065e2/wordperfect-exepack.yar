import "pe"
rule _WordPerfect_EXEPack_
{
	meta:
		description = "WordPerfect EXEPack"
	strings:
		$0 = {95 8C C0 05 10 00 0E 1F A3 04 00 03 06 0C 00 8E C0 8B 0E 06 00 8B F9 4F 8B F7 FD F3 A4 8B 16 0E 00 50 B8 39 00 50 CB 8C D8 2B C2 8E D8 8E C0 BF 0F 00 8B F7 B1 10 B0 FF F3 AE 47 87 F7 8C C8 2B C2 8E C0 B1 04 8B C6 F7 D0 D3 E8 8C DA 2B D0 73}
	condition:
		$0 at pe.entry_point
}