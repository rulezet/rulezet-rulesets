import "pe"
rule _XtremeProtector_107__Rafael_Ahucha__Sergio_Lara_
{
	meta:
		description = "Xtreme-Protector 1.07 -> Rafael Ahucha & Sergio Lara"
	strings:
		$0 = {B8 ?? ?? ?? 00 B9 8E ?? ?? 00 50 51 E8 1E 00 00 00 E8 00 00 00 00 58 2D 16 00 00 00 B9}
	condition:
		$0 at pe.entry_point
}