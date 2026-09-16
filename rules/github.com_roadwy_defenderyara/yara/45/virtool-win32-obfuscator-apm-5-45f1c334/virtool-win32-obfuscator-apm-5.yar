rule VirTool_Win32_Obfuscator_APM_5{
	meta:
		description = "VirTool:Win32/Obfuscator.APM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {56 8b 46 3c 4f 23 c7 40 8b ce 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 8b 04 31 03 f8 8b 46 14 } 		$a_01_1 = {57 8b 47 3c 4a 23 c2 40 8b cf 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 8b 04 31 03 f8 8b 46 14 } 		$a_03_2 = {47 8b 47 3b 4a 4f 23 c2 [0-18] 83 c1 77 03 c1 8b 00 5e 8b fe 03 f0 59 [0-20] 8b 04 31 03 f8 8b 46 14 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}