rule _Private_EXE_Protector_20__SetiSoft_
{
	meta:
		description = "Private EXE Protector 2.0 -> SetiSoft"
	strings:
		$0 = {89 ?? ?? 38 00 00 00 8B ?? 00 00 00 00 81 ?? ?? ?? ?? ?? 89 ?? 00 00 00 00 81 ?? 04 00 00 00 81 ?? 04 00 00 00 81 ?? 00 00 00 00 0F 85 D6 FF FF FF}
	condition:
		$0
}