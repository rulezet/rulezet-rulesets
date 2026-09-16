import "pe"
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_60__70__ASM_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0 / ASM)"
	strings:
		$0 = {E8 01 00 00 00 5A 5E E8 02 00 00 00 BA DD 5E 03 F2 EB 01 64 BB 80 ?? ?? 00 8B FA EB 01 A8}
	condition:
		$0 at pe.entry_point
}