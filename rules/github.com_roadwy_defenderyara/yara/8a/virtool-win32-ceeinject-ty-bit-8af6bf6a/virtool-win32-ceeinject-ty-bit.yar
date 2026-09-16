rule VirTool_Win32_CeeInject_TY_bit{
	meta:
		description = "VirTool:Win32/CeeInject.TY!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b d0 83 e2 03 8a 14 0a 30 14 38 40 3b c6 72 f0 } 		$a_01_1 = {8b c3 c1 e8 08 8b d3 88 19 c1 eb 18 88 41 01 c1 ea 10 33 c0 88 59 03 88 51 02 } 		$a_03_2 = {0f af c6 03 c0 03 c0 03 c0 bb ?? ?? ?? ?? 6a 01 2b d8 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}