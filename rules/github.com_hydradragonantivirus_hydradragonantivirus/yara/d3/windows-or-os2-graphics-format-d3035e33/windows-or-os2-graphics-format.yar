import "pe"
rule _Windows_or_OS2_Graphics_format_
{
	meta:
		description = "Windows or OS/2 Graphics format"
	strings:
		$0 = {42 4D}
	condition:
		$0 at pe.entry_point
}