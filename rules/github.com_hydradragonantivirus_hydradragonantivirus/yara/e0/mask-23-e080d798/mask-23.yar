import "pe"
rule _Mask_23_
{
	meta:
		description = "Mask 2.3"
	strings:
		$0 = {55 57 CD 03 FC 4D 41 53 4B FA 8B EC 83 6E 06 03 FF 76 06 5D 49 E8 00 00 5B 81 EB A6 05 50 D6 51 52 56}
	condition:
		$0 at pe.entry_point
}