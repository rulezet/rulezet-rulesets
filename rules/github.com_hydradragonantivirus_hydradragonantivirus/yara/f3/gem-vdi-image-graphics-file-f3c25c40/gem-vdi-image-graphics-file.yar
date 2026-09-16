import "pe"
rule _Gem_VDI_Image_graphics_file_
{
	meta:
		description = "Gem VDI Image graphics file"
	strings:
		$0 = {00 01 00 ?? 00 ?? 00 01}
	condition:
		$0 at pe.entry_point
}