rule VirTool_Win32_CeeInject_TV_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TV!bit,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 8a 00 32 05 ?? ?? ?? ?? 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10 41 4b 75 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}