rule VirTool_Win32_Obfuscator_RN_2{
	meta:
		description = "VirTool:Win32/Obfuscator.RN,SIGNATURE_TYPE_PEHSTR_EXT,06 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 00 57 00 45 00 6a 00 6c 00 6b 00 6a 00 70 00 6f 00 69 00 70 00 6f 00 69 00 64 00 66 00 6a 00 68 00 73 00 6b 00 6a 00 64 00 68 00 66 00 00 00 } 		$a_01_1 = {54 00 3a 00 5c 00 74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 20 00 73 00 79 00 73 00 } 		$a_01_2 = {8b 5c 24 10 33 de 8d 84 18 2d 60 00 00 83 f8 08 } 		$a_01_3 = {bb fe ef ff ff 89 5d fc c7 45 fc f9 ef ff ff } 		$a_01_4 = {33 c6 03 c7 89 44 24 20 8b 44 24 14 33 c6 03 c7 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}