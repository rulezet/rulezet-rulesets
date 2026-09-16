rule VirTool_Win32_Obfuscator_VP{
	meta:
		description = "VirTool:Win32/Obfuscator.VP,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 c2 f8 4e 75 fa 5e 8a ca d2 c8 c3 } 		$a_01_1 = {80 c2 f8 4e 75 fa 5e 8a ca d2 c0 c3 } 		$a_01_2 = {73 fa 0f b6 c0 8b 44 c1 04 e9 52 ff ff ff d0 e9 3a ca 73 fa 0f b6 c9 8b 04 c8 eb 81 d0 e9 3a ca 73 fa 0f b6 c9 8b 04 c8 eb ae 32 c0 5f c9 c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}