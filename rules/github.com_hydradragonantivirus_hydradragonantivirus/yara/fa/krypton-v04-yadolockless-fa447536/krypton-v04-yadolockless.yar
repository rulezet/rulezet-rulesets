import "pe"
rule _Krypton_v04__yadolockless_
{
	meta:
		description = "Krypton v0.4 -> yado/lockless"
	strings:
		$0 = {54 E8 00 00 00 00 5D 8B C5 81 ED 61 34 ?? 00 2B 85 60 37 ?? 00 83 E8 06}
	condition:
		$0 at pe.entry_point
}