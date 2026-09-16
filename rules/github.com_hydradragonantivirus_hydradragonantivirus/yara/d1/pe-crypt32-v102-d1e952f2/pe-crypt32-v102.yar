import "pe"
rule _PE_Crypt32_v102_
{
	meta:
		description = "PE Crypt32 v1.02"
	strings:
		$0 = {E8 ?? ?? ?? ?? 5B 83 EB 05 EB 04 52 4E 44 21 EB 02 CD 20}
	condition:
		$0 at pe.entry_point
}