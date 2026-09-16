import "pe"
rule _ARM_Protector_02_SMoKE_
{
	meta:
		description = "ARM Protector 0.2-> SMoKE"
	strings:
		$0 = {E8 04 00 00 00 83 60 EB 0C 5D EB 05 45 55 EB 04 B8 EB F9 00 C3 E8 00 00 00 00 5D EB 01 00 81 ED 09 20 40 00 EB 02 83 09 8D B5 9A 20 40 00 EB 02 83 09 BA 0B 12 00 00 EB 01 00 8D 8D A5 32 40 00}
	condition:
		$0 at pe.entry_point
}