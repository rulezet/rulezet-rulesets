rule _NsPack_V2X__LiuXingPing_
{
	meta:
		description = "NsPack V2.X -> LiuXingPing"
	strings:
		$0 = {6E 73 70 61 63 6B 24 40}
	condition:
		$0
}