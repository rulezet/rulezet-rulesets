rule VirTool_Win32_CeeInject_UL_bit_2{
	meta:
		description = "VirTool:Win32/CeeInject.UL!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 51 8a 45 10 88 45 ?? 8b 4d 08 03 4d 0c 8a 55 ?? 88 11 8b e5 5d } 		$a_01_1 = {55 8b ec 8b 45 08 03 45 0c 8b 4d 10 8a 10 88 11 5d } 		$a_03_2 = {2b d8 88 5d 90 09 08 00 8b 54 85 ?? 8d 44 16 } 		$a_03_3 = {51 6a 00 6a 00 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 89 45 ?? 8b 5d ?? ff 75 ?? ff 75 ?? 68 ?? ?? ?? ?? 6a 00 6a ff 5a ff d3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}