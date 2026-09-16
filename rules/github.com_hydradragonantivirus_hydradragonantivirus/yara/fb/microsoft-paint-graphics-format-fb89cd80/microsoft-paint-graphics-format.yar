import "pe"
rule _Microsoft_Paint_Graphics_format_
{
	meta:
		description = "Microsoft Paint Graphics format"
	strings:
		$0 = {4C 69 6E 53}
	condition:
		$0 at pe.entry_point
}