rule VirTool_Win32_Obfuscator_AOH{
	meta:
		description = "VirTool:Win32/Obfuscator.AOH,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 81 fd 00 fd 90 13 89 ec 5d } 		$a_03_1 = {66 81 fd 00 fe 90 13 89 ec 5d } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}