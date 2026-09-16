import "pe"
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_60__ASM_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / ASM)"
	strings:
		$0 = {F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68}
	condition:
		$0 at pe.entry_point
}