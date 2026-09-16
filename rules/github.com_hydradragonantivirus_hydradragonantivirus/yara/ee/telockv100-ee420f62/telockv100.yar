import "pe"
rule tElockv100 : tE
{
	meta:
		author="_pusher_"
		date = "2015-11"
	strings:
		$a0 = { E9 E5 E2 FF FF }
	condition:
		$a0 at pe.entry_point
}