import "pe"
rule _UPX_v071_DLL_
{
	meta:
		description = "UPX v0.71 [DLL"
	strings:
		$0 = {80 7C 24 08 01 0F 85 95 01 00 00 60 E8 00 00 00 00 83}
	condition:
		$0 at pe.entry_point
}