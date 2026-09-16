import "pe"
rule _Thinstall_V24X25X__Jitit_
{
	meta:
		description = "Thinstall V2.4X-2.5X -> Jitit"
	strings:
		$0 = {55 8B EC B8 ?? ?? ?? ?? BB ?? ?? ?? ?? 50 E8 00 00 00 00 58}
	condition:
		$0 at pe.entry_point
}