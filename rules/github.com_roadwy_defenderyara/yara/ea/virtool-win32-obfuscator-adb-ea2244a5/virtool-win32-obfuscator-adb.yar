rule VirTool_Win32_Obfuscator_ADB{
	meta:
		description = "VirTool:Win32/Obfuscator.ADB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {a5 71 19 a6 } 		$a_01_1 = {b1 34 61 d5 } 		$a_01_2 = {41 6e 6f 74 68 65 72 53 74 72 69 6e 67 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}