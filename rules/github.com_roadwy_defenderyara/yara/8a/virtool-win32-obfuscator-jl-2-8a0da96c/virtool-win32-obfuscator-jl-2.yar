rule VirTool_Win32_Obfuscator_JL_2{
	meta:
		description = "VirTool:Win32/Obfuscator.JL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {ac 4f 8a 27 88 66 ?? 88 07 e2 f5 5e } 		$a_01_1 = {8b c3 03 43 3c 81 78 50 00 80 04 00 76 } 		$a_01_2 = {50 33 c2 5a ab 83 e9 03 e2 df } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}