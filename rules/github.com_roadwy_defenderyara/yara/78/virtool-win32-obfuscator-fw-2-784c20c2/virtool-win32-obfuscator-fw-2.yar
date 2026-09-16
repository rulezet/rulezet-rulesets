rule VirTool_Win32_Obfuscator_FW_2{
	meta:
		description = "VirTool:Win32/Obfuscator.FW,SIGNATURE_TYPE_PEHSTR_EXT,07 00 03 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 1b 56 ad f6 } 		$a_01_1 = {68 c1 09 69 c7 } 		$a_01_2 = {66 81 38 4d 5a } 		$a_03_3 = {8d 9b 80 00 00 00 90 18 8b 1b } 		$a_01_4 = {66 8e e8 66 8c e8 } 		$a_03_5 = {66 8f 40 16 90 18 0f b7 4b 06 } 		$a_01_6 = {35 da 8c a9 89 } 		$a_01_7 = {35 82 fa 50 4b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=3
 
}