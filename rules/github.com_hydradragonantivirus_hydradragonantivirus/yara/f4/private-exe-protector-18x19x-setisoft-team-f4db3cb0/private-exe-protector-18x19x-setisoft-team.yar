import "pe"
rule _Private_exe_Protector_18X19X__SetiSoft_Team_
{
	meta:
		description = "Private exe Protector 1.8X-1.9X -> SetiSoft Team"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00}
	condition:
		$0 at pe.entry_point
}