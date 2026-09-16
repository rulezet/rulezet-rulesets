import "pe"
rule _RJoiner_by_Vaska_Sign_from_pinch_25032007_1700_
{
	meta:
		description = "RJoiner by Vaska (Sign from pinch 25.03.2007 17:00)"
	strings:
		$0 = {E8 03 FD FF FF 6A 00 E8 0C 00 00 00 FF 25 6C 10 40 00 FF 25 70 10 40 00 FF 25 74 10 40 00 FF 25 78 10 40 00 FF 25 7C 10 40 00 FF 25 80 10 40 00 FF 25 84 10 40 00 FF 25 88 10 40 00 FF 25 8C 10}
	condition:
		$0 at pe.entry_point
}