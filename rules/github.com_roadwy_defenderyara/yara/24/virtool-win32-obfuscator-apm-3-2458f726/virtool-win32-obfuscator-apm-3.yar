rule VirTool_Win32_Obfuscator_APM_3{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,42 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b cf 83 c1 77 [0-18] 03 f8 8b 46 14 } 		$a_03_1 = {f3 33 c2 5a 47 [0-18] e2 [18-38] [0-40] ad 4e 4e 4e 75 } 		$a_03_2 = {54 5f 41 89 07 51 58 [0-10] 8b 06 03 f2 89 07 03 fa e2 f6 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=6
 
}