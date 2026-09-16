rule _nSpack_V13__LiuXingPing_
{
	meta:
		description = "nSpack V1.3 -> LiuXingPing"
	strings:
		$0 = {9C 60 E8 00 00 00 00 5D B8 B3 85 40 00 2D AC 85 40 00}
	condition:
		$0 at entrypoint
}