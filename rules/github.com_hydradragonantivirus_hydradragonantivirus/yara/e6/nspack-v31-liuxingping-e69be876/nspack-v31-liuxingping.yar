import "pe"
rule _NsPacK_V31__LiuXingPing_
{
	meta:
		description = "NsPacK V3.1 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D 83 ED 07 8D 9D ?? ?? ?? ?? 8A 03 3C 00 74}
	condition:
		$0 at pe.entry_point
}