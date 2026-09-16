import "pe"
rule _WWPack32_v1x_
{
	meta:
		description = "WWPack32 v1.x"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5D 8B CD 81 ED 7A 29 40 ?? 89 AD 0F 6D}
	condition:
		$0 at pe.entry_point
}