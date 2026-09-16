rule VirTool_Win32_Obfuscator_ANM_3{
	meta:
		description = "VirTool:Win32/Obfuscator.ANM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 00 3a 07 75 ?? ?? ?? ?? ?? ?? 8a 00 3a 47 01 75 } 		$a_11_1 = {09 8a 07 3a c8 75 c0 3a 47 01 74 bb 8b 4d fc 03 ce 8a 09 3a 4f 01 75 af 01 } 		$a_8a_2 = {8b 95 90 } 	condition:
		((#a_03_0  & 1)*1+(#a_11_1  & 1)*1+(#a_8a_2  & 1)*5120) >=2
 
}