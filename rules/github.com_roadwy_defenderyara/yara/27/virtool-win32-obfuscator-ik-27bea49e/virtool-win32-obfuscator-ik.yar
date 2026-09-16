rule VirTool_Win32_Obfuscator_IK{
	meta:
		description = "VirTool:Win32/Obfuscator.IK,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 46 08 8b 7e 20 8b 36 80 3f 6b 75 f3 80 7f 18 00 } 		$a_03_1 = {8a 11 84 d2 74 08 0f be d2 83 c2 ?? eb 02 33 d2 88 11 41 80 39 00 } 		$a_01_2 = {c6 40 04 75 c6 40 02 72 c6 40 06 6c c6 40 03 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}