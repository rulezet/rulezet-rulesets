rule VirTool_Win32_Obfuscator_XT{
	meta:
		description = "VirTool:Win32/Obfuscator.XT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff d3 8b f8 81 c7 4e 05 00 00 eb 02 ff d3 ff d3 3b f8 } 		$a_01_1 = {89 c3 6a 02 6a 5f 6a 00 ff d6 50 ff d3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}