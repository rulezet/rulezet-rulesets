rule VirTool_Win32_CeeInject_TU_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TU!bit,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 db 33 db a1 ?? ?? ?? ?? 03 c3 8a 00 ?? ?? ?? ?? 89 db ?? ?? ?? ?? ?? ?? ?? ?? 34 16 8b 15 ?? ?? ?? ?? 03 d3 88 02 89 c0 } 		$a_00_1 = {8b c1 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 8a 00 50 8b c7 33 d2 52 50 8b c3 99 03 04 24 13 54 24 04 83 c4 08 5a 88 10 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}