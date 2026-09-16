import "pe"
rule _Sun_Icon_Graphics_format_
{
	meta:
		description = "Sun Icon Graphics format"
	strings:
		$0 = {2F 2A 20 46 6F 72 6D 61 74 5F 76 65 72 73 69 6F 6E 3D 31 2C}
	condition:
		$0 at pe.entry_point
}