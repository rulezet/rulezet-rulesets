rule VirTool_Win32_Obfuscator_API{
	meta:
		description = "VirTool:Win32/Obfuscator.API,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c7 04 83 e9 04 83 f9 00 90 13 90 13 31 } 		$a_03_1 = {83 c7 04 83 e9 04 90 13 8b 02 83 c2 04 89 07 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}