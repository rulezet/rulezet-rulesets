import "pe"
rule _ATT_Group_4_Graphics_format_
{
	meta:
		description = "AT&T Group 4 Graphics format"
	strings:
		$0 = {01 00 ?? 00 3A 03}
	condition:
		$0 at pe.entry_point
}