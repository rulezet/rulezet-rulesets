import "pe"
rule _CorelDraw_8_CDR_Graphics_format_
{
	meta:
		description = "CorelDraw 8 CDR Graphics format"
	strings:
		$0 = {52 49 46 46 ?? ?? ?? ?? 43 44 52 38}
	condition:
		$0 at pe.entry_point
}