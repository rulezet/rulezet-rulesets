import "pe"
rule _Vcasm_Protector_V1X__vcasm_
{
	meta:
		description = "Vcasm Protector V1.X -> vcasm"
	strings:
		$0 = {EB ?? 5B 56 50 72 6F 74 65 63 74 5D}
	condition:
		$0 at pe.entry_point
}