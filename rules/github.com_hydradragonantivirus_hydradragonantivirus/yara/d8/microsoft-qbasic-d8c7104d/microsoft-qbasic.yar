import "pe"
rule _Microsoft_QBasic_
{
	meta:
		description = "Microsoft QBasic"
	strings:
		$0 = {B4 30 CD 21 3C 02 73 02 CD 20 BF 00 00 8B 36 02 00 2B F7 81 FE 00 10 72 03 BE 00 10 FA 8E D7 81 C4 00 00 FB 73 0B 33 C0 36 C7 06 00 00 00 00 EB 7D 83 E4 FE 36 89 26 00 00 8B C6 B1 04 D3 E0 48 36 A3 00 00 03 F7 89 36 02 00 8C C3 2B DE F7 DB}
	condition:
		$0 at pe.entry_point
}