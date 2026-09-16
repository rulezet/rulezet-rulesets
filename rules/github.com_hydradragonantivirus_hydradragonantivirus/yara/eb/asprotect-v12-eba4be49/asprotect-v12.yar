import "pe"
rule _ASProtect_v12_
{
	meta:
		description = "ASProtect v1.2"
	strings:
		$0 = {68 01 C3 AA ??}
	condition:
		$0 at pe.entry_point
}