import "pe"
rule _NoobyProtect_1x__1710__Nooby_
{
	meta:
		description = "NoobyProtect 1.x - 1.7.1.0 -> Nooby"
	strings:
		$0 = {00 00 00 4E 6F 6F 62 79 50 72 6F 74 65 63 74 20}
	condition:
		$0 at pe.entry_point
}