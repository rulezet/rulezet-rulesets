import "pe"
rule _ADEX_Graphics_format_
{
	meta:
		description = "ADEX Graphics format"
	strings:
		$0 = {50 49 43 54 00 08 ?? 02}
	condition:
		$0 at pe.entry_point
}