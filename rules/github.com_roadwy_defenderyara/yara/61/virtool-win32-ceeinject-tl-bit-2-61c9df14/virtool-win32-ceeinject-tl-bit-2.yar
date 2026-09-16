rule VirTool_Win32_CeeInject_TL_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.TL!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b c7 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 } 		$a_03_1 = {8a 00 50 8b c6 33 d2 52 50 8b c1 99 03 04 24 13 54 24 04 71 ?? e8 ?? ?? ?? ?? 83 c4 08 5a 88 10 } 		$a_03_2 = {8b c3 33 d2 52 50 8b 06 99 03 04 24 13 54 24 04 71 05 e8 ?? ?? ?? ?? 83 c4 08 32 0d ?? ?? ?? ?? 88 08 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}