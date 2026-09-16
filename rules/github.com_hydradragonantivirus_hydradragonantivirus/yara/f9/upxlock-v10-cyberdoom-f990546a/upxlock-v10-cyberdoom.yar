import "pe"
rule _UPXLock_v10__CyberDoom_
{
	meta:
		description = "UPXLock v1.0 -> CyberDoom"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? ?? 60 E8 2B 03 00 00}
	condition:
		$0 at pe.entry_point
}