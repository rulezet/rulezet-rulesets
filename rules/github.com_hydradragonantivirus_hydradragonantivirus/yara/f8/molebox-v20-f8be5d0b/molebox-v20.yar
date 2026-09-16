rule _MoleBox_v20_
{
	meta:
		description = "MoleBox v2.0"
	strings:
		$0 = {E8 ?? ?? ?? ?? 60 E8 4F}
	condition:
		$0
}