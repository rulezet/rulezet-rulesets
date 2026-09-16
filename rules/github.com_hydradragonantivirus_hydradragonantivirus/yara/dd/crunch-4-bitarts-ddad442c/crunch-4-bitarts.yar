import "pe"
rule _Crunch_4__BitArts_
{
	meta:
		description = "Crunch 4 -> Bit-Arts"
	strings:
		$0 = {EB 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 55 E8 00 00 00 00}
	condition:
		$0 at pe.entry_point
}