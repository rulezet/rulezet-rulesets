rule VirTool_Win32_Obfuscator_UG{
	meta:
		description = "VirTool:Win32/Obfuscator.UG,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 f2 6c 80 c2 4d 88 11 } 		$a_01_1 = {50 68 c2 24 53 00 05 b6 da ff ff } 		$a_01_2 = {8b 4d ec 33 ce 33 c6 8d 84 01 4a 25 00 00 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}