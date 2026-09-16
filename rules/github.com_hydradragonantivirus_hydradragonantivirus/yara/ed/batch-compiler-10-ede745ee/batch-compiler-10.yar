import "pe"
rule _Batch_Compiler_10_
{
	meta:
		description = "Batch Compiler 1.0"
	strings:
		$0 = {FC BD 58 01 8B 6E 00 8B 66 02 8B 5E 04 B4 4A CD 21 A1 2C 00 89 46 1A 8B 5E 00 FF E3}
	condition:
		$0 at pe.entry_point
}