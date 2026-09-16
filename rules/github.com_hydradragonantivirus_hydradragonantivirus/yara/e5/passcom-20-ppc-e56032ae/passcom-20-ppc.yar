import "pe"
rule _PassCOM_20__PPC_
{
	meta:
		description = "PassCOM 2.0 / PPC"
	strings:
		$0 = {BE 00 00 B9 64 01 87}
	condition:
		$0 at pe.entry_point
}