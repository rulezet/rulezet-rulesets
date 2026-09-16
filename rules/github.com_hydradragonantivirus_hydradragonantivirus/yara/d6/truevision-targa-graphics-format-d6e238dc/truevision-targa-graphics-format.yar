import "pe"
rule _TrueVision_Targa_Graphics_format_
{
	meta:
		description = "TrueVision Targa Graphics format"
	strings:
		$0 = {00 00 02 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}