import "pe"
rule _PE_Crypt_v102_
{
	meta:
		description = "PE Crypt v1.02"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5B 83 EB 52 4E 44}
	condition:
		$0 at pe.entry_point
}