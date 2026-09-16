rule VirTool_Win32_Obfuscator_BZP{
	meta:
		description = "VirTool:Win32/Obfuscator.BZP,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 c1 0b 04 04 f6 e9 8a d3 02 d2 02 c2 30 04 3b a1 } 		$a_01_1 = {b8 00 f4 12 00 e9 e6 11 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}