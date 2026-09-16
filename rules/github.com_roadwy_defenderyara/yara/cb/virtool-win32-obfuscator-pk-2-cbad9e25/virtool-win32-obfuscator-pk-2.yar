rule VirTool_Win32_Obfuscator_PK_2{
	meta:
		description = "VirTool:Win32/Obfuscator.PK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {81 ff 00 20 00 00 0f 82 90 16 c6 85 e5 fd ff ff 00 } 		$a_03_1 = {8d 44 95 e4 [0-10] 8b 08 } 		$a_01_2 = {ff 74 b5 e4 } 		$a_03_3 = {39 08 0f 84 ?? ?? 00 00 [0-10] 8b d8 8b 03 [0-10] 8a 04 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}