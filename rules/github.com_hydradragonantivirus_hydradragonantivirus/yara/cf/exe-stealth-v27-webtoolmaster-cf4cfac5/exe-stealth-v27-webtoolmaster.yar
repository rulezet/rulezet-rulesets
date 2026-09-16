import "pe"
rule _EXE_Stealth_v27__WebToolMaster_
{
	meta:
		description = "EXE Stealth v2.7 -> WebToolMaster"
	strings:
		$0 = {EB 00 60 EB 00 E8 00 00 00 00 5D 81 ED D3 26 40}
	condition:
		$0 at pe.entry_point
}