import "pe"
rule _Upack_v032_Beta_
{
	meta:
		description = "Upack v0.32 Beta"
	strings:
		$0 = {BE 88 01 ?? ?? AD 50 ?? AD 91 ?? F3 A5}
	condition:
		$0 at pe.entry_point
}