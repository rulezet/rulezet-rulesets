import "pe"
rule _Hitachi_Raster_Format_graphics_format_
{
	meta:
		description = "Hitachi Raster Format graphics format"
	strings:
		$0 = {43 41 44 43 2F 4B 52 20 52 53 54}
	condition:
		$0 at pe.entry_point
}