import "pe"
rule _iPB_Protect_013__017__forgot_
{
	meta:
		description = "iPB Protect 0.1.3 - 0.1.7 -> forgot"
	strings:
		$0 = {55 8B EC 6A FF 68 4B 43 55 46 68 54 49 48 53 64 A1 00 00 00 00}
	condition:
		$0 at pe.entry_point
}