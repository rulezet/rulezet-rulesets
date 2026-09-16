import "pe"
rule _Borland_Delphi_30_
{
	meta:
		description = "Borland Delphi 3.0"
	strings:
		$0 = {55 8B EC 83 C4 F4 53 56 57}
	condition:
		$0 at pe.entry_point
}