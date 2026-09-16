import "pe"
rule _Excalibur_V103__forgot_
{
	meta:
		description = "Excalibur V1.03 -> forgot"
	strings:
		$0 = {E9 00 00 00 00 60 E8 14 00 00 00 5D 81 ED 00 00 00 00 6A 45 E8 A3 00 00 00 68 00 00 00 00 E8 58 61 EB 39}
	condition:
		$0 at pe.entry_point
}