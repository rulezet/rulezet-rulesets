import "pe"
rule _PCGuard_303__305__Blagoje_Ceklic_
{
	meta:
		description = "PC-Guard 3.03 - 3.05 -> Blagoje Ceklic"
	strings:
		$0 = {55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01}
	condition:
		$0 at pe.entry_point
}