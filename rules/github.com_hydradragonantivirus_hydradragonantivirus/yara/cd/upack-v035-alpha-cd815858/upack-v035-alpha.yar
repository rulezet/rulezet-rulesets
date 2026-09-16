import "pe"
rule _Upack_v035_alpha_
{
	meta:
		description = "Upack v0.35 alpha"
	strings:
		$0 = {8B F2 8B CA 03 4C 19 1C 03 54 1A 20}
	condition:
		$0 at pe.entry_point
}