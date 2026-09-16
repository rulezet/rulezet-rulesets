import "pe"
rule _shoooos_Pack__shoooo_
{
	meta:
		description = "shoooo's Pack -> shoooo"
	strings:
		$0 = {68 ?? ?? ?? ?? E8 01 00 00 00 C3 C3 11 55 07 8B EC B8 ?? ?? ?? ?? E8}
	condition:
		$0 at pe.entry_point
}