import "pe"
rule _Erdas_LANGIS_Image_graphics_format_
{
	meta:
		description = "Erdas LAN/GIS Image graphics format"
	strings:
		$0 = {48 45 41 44 37 34 00 00 03 00}
	condition:
		$0 at pe.entry_point
}