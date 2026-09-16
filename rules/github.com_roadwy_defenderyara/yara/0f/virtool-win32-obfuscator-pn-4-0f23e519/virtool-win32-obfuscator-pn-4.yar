rule VirTool_Win32_Obfuscator_PN_4{
	meta:
		description = "VirTool:Win32/Obfuscator.PN,SIGNATURE_TYPE_PEHSTR_EXT,64 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 80 94 01 00 00 8b 00 03 41 3c 8b (4d 14|4c 24 18) 8b 89 90 03 01 01 d4 d8 01 00 00 8b 49 14 6a 04 68 00 30 00 00 ff 70 50 6a 00 ff d1 } 		$a_03_1 = {3a c8 75 0f 8d 45 ?? e8 ?? ?? ff ff 8b 4d ?? 3b c1 74 ?? 8b 45 fc } 		$a_03_2 = {8a 0a 80 f9 ?? 75 ?? c6 00 00 8b 86 88 01 00 00 03 c7 } 	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}