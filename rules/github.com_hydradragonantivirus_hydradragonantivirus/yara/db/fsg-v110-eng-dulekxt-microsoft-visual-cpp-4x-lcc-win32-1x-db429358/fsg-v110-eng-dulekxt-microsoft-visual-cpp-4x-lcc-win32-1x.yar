import "pe"
rule _FSG_v110_Eng__dulekxt__Microsoft_Visual_Cpp_4x__LCC_Win32_1x_
{
	meta:
		description = "FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 4.x / LCC Win32 1.x)"
	strings:
		$0 = {2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 ?? ?? 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB}
	condition:
		$0 at pe.entry_point
}