import "pe"
rule _OptLink_Pass_2_
{
	meta:
		description = "OptLink Pass 2"
	strings:
		$0 = {87 C0 EB 0B 00 01 02 D8 01 00 00 02 00 00 00 FC 8C DA 83 C2 10 52 16 07 0E 1F 01 16 09 00 01 16 0D 00 33 F6 33 FF B9 00 00 F3 A5 06 B8 31 00 50 CB FD 8B 1E 00 00 B9 00 10 3B D9 77 02 8B CB 2B D9 8C D8 2B C1 8E D8 8C C0 2B C1 8E C0 03 C9 03}
	condition:
		$0 at pe.entry_point
}