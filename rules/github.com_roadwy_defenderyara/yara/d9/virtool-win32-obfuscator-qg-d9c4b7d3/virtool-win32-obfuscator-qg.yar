rule VirTool_Win32_Obfuscator_QG{
	meta:
		description = "VirTool:Win32/Obfuscator.QG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 54 3e ff 09 e9 } 		$a_01_1 = {3d f0 35 05 00 e9 } 		$a_01_2 = {68 20 10 dc ba e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}