rule VirTool_Win32_Obfuscator_JL{
	meta:
		description = "VirTool:Win32/Obfuscator.JL,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 88 28 03 00 00 03 48 08 } 		$a_01_1 = {c1 ea 02 83 44 24 20 04 68 f8 ff fd 7f eb } 		$a_01_2 = {29 4c 24 20 8b 07 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}