import "pe"
rule _Vx_Sonik_Youth_
{
	meta:
		description = "Vx: Sonik Youth"
	strings:
		$0 = {8A 16 02 00 8A 07 32 C2 88 07 43 FE C2 81 FB}
	condition:
		$0 at pe.entry_point
}