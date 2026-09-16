import "pe"
rule _eXpressor_v13x_
{
	meta:
		description = "eXpressor v1.3x"
	strings:
		$0 = {55 8B EC 83 EC 58 53 56 57 83 65 DC ?? F3 EB 0C 65 58 50 72 2D 76 2E 31 2E 34}
	condition:
		$0 at pe.entry_point
}