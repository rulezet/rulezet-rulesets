import "pe"
rule _Vx_Trivial46_
{
	meta:
		description = "Vx: Trivial.46"
	strings:
		$0 = {B4 4E B1 20 BA ?? ?? CD 21 BA ?? ?? B8 ?? 3D CD 21}
	condition:
		$0 at pe.entry_point
}