import "pe"
rule _EXEStealth_275__WebtoolMaster_
{
	meta:
		description = "EXEStealth 2.75 -> WebtoolMaster"
	strings:
		$0 = {90 60 90 E8 00 00 00 00 5D 81 ED D1 27 40 00 B9 15 00 00 00}
	condition:
		$0 at pe.entry_point
}