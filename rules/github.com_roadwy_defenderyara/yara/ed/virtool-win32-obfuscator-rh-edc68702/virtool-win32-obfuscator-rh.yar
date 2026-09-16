rule VirTool_Win32_Obfuscator_RH{
	meta:
		description = "VirTool:Win32/Obfuscator.RH,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {46 3a 5c 4a 48 46 48 47 46 48 47 46 5c 47 48 4a 47 4a 48 47 48 5c 64 67 66 6a 67 68 67 2e 65 78 65 20 2f 6b 73 64 67 66 68 67 68 73 00 } 		$a_01_1 = {57 00 48 00 47 00 46 00 4a 00 48 00 47 00 48 00 00 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}