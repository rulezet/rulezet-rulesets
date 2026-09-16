import "pe"
rule _eXpressor_v145__CGSoftLabs_
{
	meta:
		description = "eXpressor v1.4.5 -> CGSoftLabs"
	strings:
		$0 = {55 8B EC 83 EC 58 53 56 57 83 65 DC 00 F3 EB 0C}
	condition:
		$0 at pe.entry_point
}