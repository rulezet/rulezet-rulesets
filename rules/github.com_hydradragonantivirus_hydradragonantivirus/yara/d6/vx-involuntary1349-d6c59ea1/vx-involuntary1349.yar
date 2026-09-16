import "pe"
rule _Vx_Involuntary1349_
{
	meta:
		description = "Vx: Involuntary.1349"
	strings:
		$0 = {BA ?? ?? B9 ?? ?? 8C DD ?? 8C C8 ?? 8E D8 8E C0 33 F6 8B FE FC ?? ?? AD ?? 33 C2 AB}
	condition:
		$0 at pe.entry_point
}