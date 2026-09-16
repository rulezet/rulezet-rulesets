import "pe"
rule _DOS32_33_
{
	meta:
		description = "DOS32 3.3"
	strings:
		$0 = {0E 1F FC 9C 5B 8B C3 80 F4 40 50 9D 9C 58 3A E7 75 0B BA 87 20 B4 09 CD 21 B4 4C CD 21 8C 06 CA 00 26 A1 2C 00 A3 C8 00 8C 0E 98 00 8C 06 9C 00 8C 06 A0 00 0E 07 33 C0 BF A0 22 B9 A0 51 2B CF D1 E9 F3 AB BA EE 0D 81 EA C4 47 B9 6A 10 BB BF}
	condition:
		$0 at pe.entry_point
}