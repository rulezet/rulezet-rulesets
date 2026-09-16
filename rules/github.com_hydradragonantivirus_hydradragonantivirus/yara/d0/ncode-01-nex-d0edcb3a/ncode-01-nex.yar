import "pe"
rule _NCode_01__NEX_
{
	meta:
		description = "N-Code 0.1 -> NEX"
	strings:
		$0 = {BB E8 03 00 00 81 C3 E8 03 00 00 B8 05 00 00 00 B9 73 00 00 00 01 C8 83 E8 32 90 90 90 90 6B C0 02 90 68 FF 64 24 F0 90 90 90 90 90 68 58 58 58 58 FF D4 50 8B 40 F2 05 B0 95 F6 95 0F 85 01 81 BB FF 68}
	condition:
		$0 at pe.entry_point
}