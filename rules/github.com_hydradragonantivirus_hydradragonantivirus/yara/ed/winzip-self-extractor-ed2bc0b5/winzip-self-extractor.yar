import "pe"
rule _WinZIP_Self_Extractor_
{
	meta:
		description = "WinZIP Self Extractor"
	strings:
		$0 = {33 ED 55 9A FF FF 00 00 0B C0 74 EE 81 C1 00 01 72 E8 89 0E 90 03 89 36 92 03 89 3E 94 03 89 1E 96 03 8C 06 98 03 89 16 9A 03 33 C0 50 9A FF FF 00 00 FF 36 94 03 9A FF FF 00 00 0B C0 74 BB FF 36 94 03 FF 36 92 03 FF 36 98 03 FF 36 96 03 FF}
	condition:
		$0 at pe.entry_point
}