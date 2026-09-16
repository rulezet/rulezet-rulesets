import "pe"
rule _UPXLock_v11__CyberDoom__Bob_
{
	meta:
		description = "UPXLock v1.1 -> CyberDoom & Bob"
	strings:
		$0 = {60 E8 ?? ?? ?? ?? 5D 81 ED ?? ?? ?? 00 60}
	condition:
		$0 at pe.entry_point
}