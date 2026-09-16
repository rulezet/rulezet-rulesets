import "pe"
rule _Vx_Hafen809_
{
	meta:
		description = "Vx: Hafen.809"
	strings:
		$0 = {E8 ?? ?? 1C ?? 81 EE ?? ?? 50 1E 06 8C C8 8E D8 06 33 C0 8E C0 26 ?? ?? ?? 07 3D}
	condition:
		$0 at pe.entry_point
}