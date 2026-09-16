import "pe"
rule _yodas_Protector_10x__Ashkbiz_Danehkar_
{
	meta:
		description = "yoda's Protector 1.0x -> Ashkbiz Danehkar"
	strings:
		$0 = {55 8B EC 53 56 57 E8 03 00 00 00 EB 01}
	condition:
		$0 at pe.entry_point
}