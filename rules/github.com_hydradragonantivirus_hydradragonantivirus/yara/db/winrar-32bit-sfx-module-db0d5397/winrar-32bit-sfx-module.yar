import "pe"
rule _WinRAR_32bit_SFX_Module_
{
	meta:
		description = "WinRAR 32-bit SFX Module"
	strings:
		$0 = {55 8B EC 81 EC 04 ?? ?? 53 56 57 6A FF 15}
	condition:
		$0 at pe.entry_point
}