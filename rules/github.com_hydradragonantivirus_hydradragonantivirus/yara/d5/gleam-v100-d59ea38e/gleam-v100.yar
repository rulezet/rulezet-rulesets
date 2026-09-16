import "pe"
rule _Gleam_v100_
{
	meta:
		description = "Gleam v1.00"
	strings:
		$0 = {55 8B EC 83 C4 F0 60 E8 51 FF FF}
	condition:
		$0 at pe.entry_point
}