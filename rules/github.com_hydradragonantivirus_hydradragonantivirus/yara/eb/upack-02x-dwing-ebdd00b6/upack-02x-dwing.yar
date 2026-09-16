import "pe"
rule _Upack_02x__Dwing_
{
	meta:
		description = "Upack 0.2x -> Dwing"
	strings:
		$0 = {BE 88 01 40 00 AD 8B F8}
	condition:
		$0 at pe.entry_point
}