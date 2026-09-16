rule VirTool_Win32_Obfuscator_RN{
	meta:
		description = "VirTool:Win32/Obfuscator.RN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 fb 0f 0f 0f 0f 0f 84 } 		$a_01_1 = {81 fb 08 09 0a 0b 0f 84 } 		$a_01_2 = {4f 50 45 4e 47 6c 33 32 2e 44 4c 4c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}