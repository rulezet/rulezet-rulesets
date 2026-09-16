import "pe"
rule _Thinstall_Embedded_V2545__Jitit__Sign_by_fly_
{
	meta:
		description = "Thinstall Embedded V2.545 -> Jitit ! Sign by fly"
	strings:
		$0 = {E8 F2 FF FF FF 50 68 ?? ?? ?? ?? 68 40 1B 00 00 E8 42 FF FF FF E9 9D FF FF FF 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}