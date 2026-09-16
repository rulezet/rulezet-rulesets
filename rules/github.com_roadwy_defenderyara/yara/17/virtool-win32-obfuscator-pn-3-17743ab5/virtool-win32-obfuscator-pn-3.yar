rule VirTool_Win32_Obfuscator_PN_3{
	meta:
		description = "VirTool:Win32/Obfuscator.PN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 73 61 72 74 79 73 61 69 64 } 		$a_01_1 = {2c 6a 0c 63 88 44 24 } 		$a_01_2 = {be d6 43 d2 7d 23 8f 55 04 93 5d e0 3b d3 95 94 } 		$a_03_3 = {8d 04 0a 8a d1 80 e2 03 c1 e8 04 f6 ea b2 fe 2a d0 00 14 0f ff 45 ?? 8b 55 ?? eb ?? 8b 45 ?? 83 c1 20 3b c8 72 ?? 8b 45 ?? 33 c9 85 c0 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2) >=2
 
}