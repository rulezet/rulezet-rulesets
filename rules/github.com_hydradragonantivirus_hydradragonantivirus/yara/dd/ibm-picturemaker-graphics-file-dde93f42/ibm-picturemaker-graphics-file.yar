import "pe"
rule _IBM_PictureMaker_graphics_file_
{
	meta:
		description = "IBM PictureMaker graphics file"
	strings:
		$0 = {00 ?? C1 ?? 00 ?? ?? ?? ?? 02 00 01}
	condition:
		$0 at pe.entry_point
}