rule VirTool_Win32_Obfuscator_APM_4{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,42 00 06 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b cf 41 83 c1 76 [0-18] 03 f8 8b 46 14 } 		$a_03_1 = {8b cf 41 83 c1 [74-76] [0-18] 6a 14 8b 04 31 03 c7 8b f8 58 8b 04 30 } 		$a_01_2 = {41 8b 06 fe c0 46 fe c8 75 f6 } 		$a_03_3 = {8b c8 41 8b 06 46 3c 00 75 f8 49 89 4d ?? 8b c1 0f 85 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}