rule VirTool_Win32_Obfuscator_JK_2{
	meta:
		description = "VirTool:Win32/Obfuscator.JK,SIGNATURE_TYPE_PEHSTR_EXT,64 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {68 f2 79 36 18 } 		$a_01_1 = {68 33 00 32 00 } 		$a_01_2 = {68 23 f9 35 9d } 		$a_01_3 = {68 ee 13 4c b6 } 		$a_01_4 = {8b 54 01 50 } 		$a_01_5 = {81 c4 00 01 00 00 } 		$a_01_6 = {66 81 3e 4d 5a } 		$a_03_7 = {5f 83 ef 05 55 8b ec 81 c4 ?? ff ff ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1) >=8
 
}