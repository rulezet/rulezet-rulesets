rule _Private_exe_Protector_V18XV19X__SetiSoft_Team_
{
	meta:
		description = "Private exe Protector V1.8X-V1.9X -> SetiSoft Team"
	strings:
		$0 = {00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 44 4C 4C 00 ?? ?? ?? ?? 00 00 00 00 00 00 45 78 69 74 50 72 6F 63 65 73 73}
	condition:
		$0
}