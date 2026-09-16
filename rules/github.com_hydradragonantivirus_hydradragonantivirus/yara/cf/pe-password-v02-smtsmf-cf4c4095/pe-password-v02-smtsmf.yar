import "pe"
rule _PE_Password_v02_SMTSMF_
{
	meta:
		description = "PE Password v0.2 SMT/SMF"
	strings:
		$0 = {52 51 55 57 64 67 A1 30 ?? 85 C0 78 0D E8 58 83 C0 07 C6}
	condition:
		$0 at pe.entry_point
}