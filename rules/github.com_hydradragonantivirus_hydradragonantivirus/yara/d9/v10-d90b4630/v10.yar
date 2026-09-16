import "pe"
rule __v10___
{
	meta:
		description = "Unknown"
	strings:
		$0 = {64 A1 00 00 00 00 55 89 E5 6A FF 68 1C 30 40 00}
	condition:
		$0 at pe.entry_point
}