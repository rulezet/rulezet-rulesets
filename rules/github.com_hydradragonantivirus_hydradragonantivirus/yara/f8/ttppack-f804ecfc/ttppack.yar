import "pe"
rule _TTPpack_
{
	meta:
		description = "TTPpack"
	strings:
		$0 = {E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 F6 E8 11 00 00 00 8B 64 24 08 64 8F 05}
		$1 = {E8 00 00 00 00 5D 81 ED F5 8F 40 00 60 33 F6 E8 11 00 00 00 8B 64 24 08 64 8F 05}
	condition:
		$0 at pe.entry_point or $1 at pe.entry_point
}