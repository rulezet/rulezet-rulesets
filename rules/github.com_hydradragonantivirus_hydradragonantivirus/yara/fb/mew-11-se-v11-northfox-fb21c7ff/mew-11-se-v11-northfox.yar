import "pe"
rule _MEW_11_SE_v11__Northfox_
{
	meta:
		description = "MEW 11 SE v1.1 -> Northfox"
	strings:
		$0 = {E9 ?? ?? ?? ?? 0C ?? ?? ?? 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}