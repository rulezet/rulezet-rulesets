rule VirTool_Win32_Obfuscator_PK_3{
	meta:
		description = "VirTool:Win32/Obfuscator.PK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 40 04 8b 10 8b 00 } 		$a_01_1 = {8b 52 3c 8b 44 02 50 } 		$a_03_2 = {03 c1 8b 0d ?? ?? 40 00 8b 49 08 ff 31 ff d0 } 		$a_03_3 = {48 8a 0c 30 [0-20] 80 e9 ?? d0 c9 88 0c 30 3b c3 0f 85 90 16 48 8a } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}