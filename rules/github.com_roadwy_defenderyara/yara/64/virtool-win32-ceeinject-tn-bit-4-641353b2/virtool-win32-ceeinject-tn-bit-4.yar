rule VirTool_Win32_CeeInject_TN_bit_4{
	meta:
		description = "VirTool:Win32/CeeInject.TN!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 07 89 45 ?? 33 45 ?? 43 33 45 ?? 8a cb d3 c8 8b 4d ?? 83 c7 04 89 4d ?? 89 06 83 c6 04 4a 75 } 		$a_01_1 = {8a 14 07 32 55 0c 88 10 40 49 75 f4 } 		$a_03_2 = {8a 0f 0f b6 e8 0f b6 c9 33 e9 83 e5 0f c1 e8 04 33 04 ad ?? ?? ?? ?? c1 e9 04 8b e8 83 e5 0f 4a 33 cd c1 e8 04 47 33 04 8d } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}