import "pe"
rule _FSG_v110___dulekxt__Microsoft_Visual_Cpp_60__70_
{
	meta:
		description = "FSG v1.10  -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)"
	strings:
		$0 = {F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68}
	condition:
		$0 at pe.entry_point
}