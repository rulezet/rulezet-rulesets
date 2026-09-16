import "pe"
rule _JDPack_2x__JDPack_
{
	meta:
		description = "JDPack 2.x -> JDPack"
	strings:
		$0 = {55 8B EC 6A FF 68 68 51 40 00 68 04 25 40 00 64 A1 00 00 00 00}
	condition:
		$0 at pe.entry_point
}