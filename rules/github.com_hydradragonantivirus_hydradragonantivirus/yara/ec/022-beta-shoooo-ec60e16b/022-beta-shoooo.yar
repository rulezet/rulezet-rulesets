import "pe"
rule __022_beta__shoooo_
{
	meta:
		description = "0.22 beta -> shoooo"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8}
	condition:
		$0 at pe.entry_point
}