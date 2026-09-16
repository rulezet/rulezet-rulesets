import "pe"
rule _Special_EXE_Password_Protector_v10_
{
	meta:
		description = "Special EXE Password Protector v1.0"
	strings:
		$0 = {55 57 51 53 E8 5D 8B C5 81 ED 2B 85 83 E8 09 89 85 0F}
	condition:
		$0 at pe.entry_point
}