import "pe"
rule _Vx_GRUNT2Family_
{
	meta:
		description = "Vx: GRUNT.2.Family"
	strings:
		$0 = {48 E2 F7 C3 51 53 52 E8 DD FF 5A 5B 59 C3 B9 00 00 E2 FE C3}
	condition:
		$0 at pe.entry_point
}