import "pe"
rule _XtremeProtector_100__105__Rafael_Ahucha__Sergio_Lara_
{
	meta:
		description = "Xtreme-Protector 1.00 - 1.05 -> Rafael Ahucha & Sergio Lara"
	strings:
		$0 = {E9 ?? ?? 00 00 00 00 00 00 00 00}
	condition:
		$0 at pe.entry_point
}