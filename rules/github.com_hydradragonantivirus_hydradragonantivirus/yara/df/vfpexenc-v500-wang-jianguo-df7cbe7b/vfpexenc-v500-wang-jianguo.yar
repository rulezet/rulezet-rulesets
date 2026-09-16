import "pe"
rule _vfpexeNc_V500__Wang_JianGuo_
{
	meta:
		description = "vfp&exeNc V5.00 -> Wang JianGuo"
	strings:
		$0 = {60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC}
	condition:
		$0 at pe.entry_point
}