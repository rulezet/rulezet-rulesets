import "pe"
rule _ZCode_Win32PE_Protector_v101_
{
	meta:
		description = "ZCode Win32/PE Protector v1.01"
	strings:
		$0 = {53 51 56 E8 ?? ?? ?? ?? 5B 81 EB 08 10 ?? ?? 8D B3 34 10 ?? ?? B9 F3 03 ?? ?? BA 63 17 2A EE 31 16 83 C6}
	condition:
		$0 at pe.entry_point
}