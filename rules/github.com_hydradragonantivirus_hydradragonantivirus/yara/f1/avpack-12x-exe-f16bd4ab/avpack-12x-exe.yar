import "pe"
rule _AVPack_12x_EXE_
{
	meta:
		description = "AVPack 1.2x [EXE]"
	strings:
		$0 = {50 1E 0E 1F 16 07 33 F6 8B FE B9 10 01 FC F3 A5 06 BB 28 00 53 CB 2E 8B 16 0C 00 58 50 03 C2 2E 03 06 0E 00 BE FE FF 8B FE FD 8C D3 BD 00 10 8B CB 2B CA 51 8B CA 3B CD 76 02 8B CD 2B C5 2B DD 8E D8 8E C3 2B D1 D1 E1 D1 E1 D1 E1 F3 A5 0B D2}
	condition:
		$0 at pe.entry_point
}