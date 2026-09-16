import "pe"
rule _ASProtect_v123_RC1_
{
	meta:
		description = "ASProtect v1.23 RC1"
	strings:
		$0 = {68 01 E8 01 C3}
	condition:
		$0 at pe.entry_point
}