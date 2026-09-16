import "pe"
rule _Windows_Type_1_font_metric_file_
{
	meta:
		description = "Windows Type 1 font metric file"
	strings:
		$0 = {00 01 ?? ?? 00 00 43 6F 70 79 72 69 67 68 74 20}
	condition:
		$0 at pe.entry_point
}