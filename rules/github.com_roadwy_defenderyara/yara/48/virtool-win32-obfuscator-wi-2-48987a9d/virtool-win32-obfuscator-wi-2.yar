rule VirTool_Win32_Obfuscator_WI_2{
	meta:
		description = "VirTool:Win32/Obfuscator.WI,SIGNATURE_TYPE_PEHSTR_EXT,05 00 02 00 02 00 00 "
		
	strings :
		$a_11_0 = {8e 88 00 00 00 89 f0 05 8e 00 00 00 8b 18 53 66 8b 5c 24 02 83 c0 04 66 8b 10 66 89 1c 24 66 89 54 24 02 5e ad 81 78 10 60 00 00 40 01 } 		$a_e8_1 = {00 00 00 8b 44 24 08 50 8b 44 24 08 50 8b 44 24 08 50 31 } 	condition:
		((#a_11_0  & 1)*1+(#a_e8_1  & 1)*9472) >=2
 
}