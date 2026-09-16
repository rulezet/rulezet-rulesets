import "pe"
rule _Microsoft_Visual_Basic_v50v60_
{
	meta:
		description = "Microsoft Visual Basic v5.0/v6.0"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 ?? ?? ?? ?? 00 00 00 00 00 00 30 00 00 00}
	condition:
		$0 at pe.entry_point
}