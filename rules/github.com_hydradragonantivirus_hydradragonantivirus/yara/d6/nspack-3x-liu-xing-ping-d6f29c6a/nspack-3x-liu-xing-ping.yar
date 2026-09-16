import "pe"
rule _NSPack_3x__Liu_Xing_Ping_
{
	meta:
		description = "NSPack 3.x -> Liu Xing Ping"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 ?? ?? FF FF ?? 38 01 0F 84 ?? 02 00 00 ?? 00 01}
	condition:
		$0 at pe.entry_point
}