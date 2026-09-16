rule Themida_HiddenPEScanner : Oreans Technologies
{
	meta:
		author="_pusher_"
		date = "2016-06"
	strings:
		$a0 = { 55 8B EC E9 D1 00 00 00 B8 ?? ?? ?? ?? C1 E8 10 05 13 09 00 00 25 FF 1F 00 00 8B C8 B9 00 00 01 00 B8 ?? ?? ?? ?? 81 E1 00 06 00 00 B9 00 08 00 00 EB 42 81 F9 00 02 00 00 76 00 51 6A 00 E8 }
	condition:
		$a0
}