rule _MEW_10_by_Northfox_
{
	meta:
		description = "MEW 10 by Northfox"
	strings:
		$0 = {33 C0 E9 ?? ?? FF FF ?? 1C ?? ?? 40}
	condition:
		$0
}