import "pe"
rule _ILUCRYPT_v4015_exe_
{
	meta:
		description = "ILUCRYPT v4.015 [exe]"
	strings:
		$0 = {8B EC FA C7 46 F7 ?? ?? 42 81 FA ?? ?? 75 F9 FF 66 F7}
	condition:
		$0 at pe.entry_point
}