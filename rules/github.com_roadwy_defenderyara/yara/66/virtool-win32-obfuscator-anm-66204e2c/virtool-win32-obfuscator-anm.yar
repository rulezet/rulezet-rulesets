rule VirTool_Win32_Obfuscator_ANM{
	meta:
		description = "VirTool:Win32/Obfuscator.ANM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_13_0 = {00 3a 85 90 01 04 75 90 01 06 8a 00 3a 85 90 01 04 75 90 00 01 } 		$a_8a_1 = {8b 95 90 01 04 0f af d6 2b c2 88 85 90 01 04 eb 90 00 00 } 	condition:
		((#a_13_0  & 1)*1+(#a_8a_1  & 1)*5120) >=2
 
}