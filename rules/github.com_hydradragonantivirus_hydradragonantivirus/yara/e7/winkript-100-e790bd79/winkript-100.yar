import "pe"
rule _WinKript_100_
{
	meta:
		description = "WinKript 1.00"
	strings:
		$0 = {33 C0 8B B8 00 00 00 00 8B 90 04 00 00 00 85 FF 74 1B 33 C9 50 EB 0C 8A 04 39 C0 C8 04 34 1B 88 04 39 41 3B CA 72 F0 58 83 C0 08 EB D5 61 E9 00 00 00 FF}
	condition:
		$0 at pe.entry_point
}