import "pe"
rule _Microsoft_Visual_Basic_50_
{
	meta:
		description = "Microsoft Visual Basic 5.0"
	strings:
		$0 = {FF FF FF 00 00 00 00 00 00 30 00 00 00 40 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}