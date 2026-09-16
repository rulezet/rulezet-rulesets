rule VirTool_Win32_Obfuscator_FW{
	meta:
		description = "VirTool:Win32/Obfuscator.FW,SIGNATURE_TYPE_PEHSTR_EXT,07 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {0f c5 ca 04 } 		$a_01_1 = {81 f9 2a a0 00 00 0f 85 4b f9 ff ff } 		$a_01_2 = {64 8b 05 18 00 00 00 } 		$a_01_3 = {64 8b 0d 30 00 00 00 } 		$a_01_4 = {8a 42 ff eb } 		$a_01_5 = {81 f8 2e 00 00 c0 0f 84 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}