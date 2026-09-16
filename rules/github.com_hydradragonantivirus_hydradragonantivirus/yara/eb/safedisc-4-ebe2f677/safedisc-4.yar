import "pe"
rule _SafeDisc_4_
{
	meta:
		description = "SafeDisc 4"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F}
	condition:
		$0 at pe.entry_point
}