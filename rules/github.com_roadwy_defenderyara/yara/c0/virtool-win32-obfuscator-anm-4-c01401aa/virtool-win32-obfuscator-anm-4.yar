rule VirTool_Win32_Obfuscator_ANM_4{
	meta:
		description = "VirTool:Win32/Obfuscator.ANM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 04 00 00 "
		
	strings :
		$a_13_0 = {48 75 f6 8b 45 fc 81 c4 90 01 02 ff ff 53 56 57 8d bd 90 01 02 ff ff eb 90 00 01 } 		$a_8a_1 = {3a 17 75 90 01 01 8b 55 fc 03 d6 8a 12 3a 57 01 75 90 01 } 		$a_fc_2 = {d6 42 8a 12 3a 57 02 75 90 00 01 00 10 13 33 c0 8a 03 2b c6 88 85 90 01 02 ff ff eb 90 00 01 00 1e 13 33 c0 8a 03 8b 95 90 01 02 ff ff 8d 14 92 0f af d6 2b c2 88 85 90 01 02 ff ff eb 41 90 00 00 00 01 00 5d 04 00 00 02 40 03 80 5c 21 00 00 03 40 03 80 00 } 	condition:
		((#a_13_0  & 1)*1+(#a_8a_1  & 1)*9216+(#a_fc_2  & 1)*-29951) >=2
 
}