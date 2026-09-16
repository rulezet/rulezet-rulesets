rule VirTool_Win32_Obfuscator_ACV{
	meta:
		description = "VirTool:Win32/Obfuscator.ACV,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 01 00 04 00 00 "
		
	strings :
		$a_05_0 = {8b 55 0c 83 e2 07 83 fa 00 74 } 		$a_05_1 = {8b 4d 0c 83 e1 07 83 f9 00 74 } 		$a_05_2 = {8b 45 0c 83 e0 07 83 f8 00 74 } 		$a_05_3 = {8b 45 0c 23 45 c8 83 f8 00 74 05 e9 } 	condition:
		((#a_05_0  & 1)*1+(#a_05_1  & 1)*1+(#a_05_2  & 1)*1+(#a_05_3  & 1)*1) >=1
 
}