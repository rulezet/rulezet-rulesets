import "pe"
rule _FSG_v10_
{
	meta:
		description = "FSG v1.0"
	strings:
		$0 = {BB D0 01 40 BF 10 40 BE FC B2 80 8A 06 46 88 07 47 02 D2 75 05 8A}
	condition:
		$0 at pe.entry_point
}