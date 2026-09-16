import "pe"
rule _vcasm_10__11__vcasm_
{
	meta:
		description = "vcasm 1.0 - 1.1 -> vcasm"
	strings:
		$0 = {EB 01 9A 60}
	condition:
		$0 at pe.entry_point
}