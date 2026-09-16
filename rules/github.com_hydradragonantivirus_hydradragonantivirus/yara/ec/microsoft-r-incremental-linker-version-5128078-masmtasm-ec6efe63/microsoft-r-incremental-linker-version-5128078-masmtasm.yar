import "pe"
rule _Microsoft_R_Incremental_Linker_Version_5128078_MASMTASM_
{
	meta:
		description = "Microsoft (R) Incremental Linker Version 5.12.8078 (MASM/TASM)"
	strings:
		$0 = {6A 00 68 00 30 40 00 68 1E 30 40 00 6A 00 E8 0D 00 00 00 6A 00 E8 00 00 00 00 FF 25 00 20 40 00 FF 25 08 20 40}
	condition:
		$0 at pe.entry_point
}