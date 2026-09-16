import "pe"
rule _Safengine_Shielden_v2160_
{
	meta:
		description = "Safengine Shielden v2.1.6.0"
	strings:
		$0 = {E8 1C 00 00 00 53 61 66 65 6E 67 69 6E 65 20 53 68 69 65 6C 64 65 6E 20}
	condition:
		$0 at pe.entry_point
}