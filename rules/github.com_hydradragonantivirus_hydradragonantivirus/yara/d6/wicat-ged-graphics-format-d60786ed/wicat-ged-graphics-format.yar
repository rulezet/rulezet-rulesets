import "pe"
rule _Wicat_GED_Graphics_format_
{
	meta:
		description = "Wicat GED Graphics format"
	strings:
		$0 = {0D 00 40 00}
	condition:
		$0 at pe.entry_point
}