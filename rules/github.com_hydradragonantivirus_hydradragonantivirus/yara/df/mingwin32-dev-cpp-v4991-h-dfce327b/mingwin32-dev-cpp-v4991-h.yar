import "pe"
rule _MingWin32__Dev_Cpp_v4991_h_
{
	meta:
		description = "MingWin32 - Dev C++ v4.9.9.1 (h)"
	strings:
		$0 = {55 89 E5 83 EC 08 C7 04 24 01 00 00 00 FF 15 ?? ?? ?? 00 E8 C8 FE FF FF 90 8D B4 26 00 00 00 00 55 89 E5 83 EC 08 C7 04 24 02 00 00 00 FF 15 ?? ?? ?? 00 E8 A8 FE FF FF 90 8D B4 26 00 00 00 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 8D 74 26 00 55 8B 0D ?? ?? ?? 00 89 E5 5D FF E1 90 90 90 90 55 89 E5 5D E9 ?? ?? 00 00 90 90 90 90 90 90 90}
	condition:
		$0 at pe.entry_point
}