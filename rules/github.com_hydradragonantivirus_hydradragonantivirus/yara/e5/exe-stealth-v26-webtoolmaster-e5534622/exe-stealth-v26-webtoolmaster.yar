import "pe"
rule _EXE_Stealth_v26__WebToolMaster_
{
	meta:
		description = "EXE Stealth v2.6 -> WebToolMaster"
	strings:
		$0 = {60 EB 22 45 78 65 53 74 65 61 6C 74 68 20 2D 20}
	condition:
		$0 at pe.entry_point
}