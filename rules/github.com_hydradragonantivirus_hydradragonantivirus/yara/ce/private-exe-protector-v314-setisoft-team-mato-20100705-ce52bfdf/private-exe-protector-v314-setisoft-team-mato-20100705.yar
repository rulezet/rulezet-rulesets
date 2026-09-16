import "pe"
rule _Private_exe_Protector_V314__SetiSoft_Team__Mato__20100705_
{
	meta:
		description = "Private exe Protector V3.1.4 -> SetiSoft Team - Mato - 20100705"
	strings:
		$0 = {50 00 72 00 69 00 76 00 61 00 74 00 65 00 20 00 65 00 78 00 65 00 20 00 50 00 72 00 6F 00 74 00 65 00 63 00 74 00 6F 00 72 00 00 00 34 00 08 00 01 00 50 00 72 00 6F 00 64 00 75 00 63 00 74 00 56 00 65 00 72 00 73 00 69 00 6F 00 6E 00 00 00 33 00 2E 00 31 00 2E 00 34 00 2E 00 30}
	condition:
		$0 at pe.entry_point
}