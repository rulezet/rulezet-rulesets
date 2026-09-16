import "pe"
rule noodle2
{
	meta:
		author = "PEiD"
		description = "NoodleCrypt 2.0 -> noodlespa"
		group = "132"
		function = "0"
	strings:
		$a0 = { EB 01 9A E8 3D ?? ?? ?? EB 01 9A E8 EB 01 ?? ?? EB 01 9A E8 2C 04 ?? ?? EB 01 }
	condition:
		$a0 at pe.entry_point
}