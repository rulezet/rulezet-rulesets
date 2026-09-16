rule VirTool_Win32_Obfuscator_KC{
	meta:
		description = "VirTool:Win32/Obfuscator.KC,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 03 00 00 "
		
	strings :
		$a_05_0 = {b8 61 c4 74 e7 } 		$a_05_1 = {66 81 fa 4d 5a } 		$a_05_2 = {3d 04 d0 17 00 } 	condition:
		((#a_05_0  & 1)*1+(#a_05_1  & 1)*1+(#a_05_2  & 1)*1) >=1
 
}