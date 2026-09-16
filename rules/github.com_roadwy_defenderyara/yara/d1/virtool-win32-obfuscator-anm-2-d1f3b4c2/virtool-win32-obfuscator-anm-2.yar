rule VirTool_Win32_Obfuscator_ANM_2{
	meta:
		description = "VirTool:Win32/Obfuscator.ANM,SIGNATURE_TYPE_PEHSTR_EXT,64 00 02 00 02 00 00 "
		
	strings :
		$a_13_0 = {48 75 f6 8b 45 fc 81 c4 90 01 02 ff ff 53 56 57 8d bd 90 01 02 ff ff eb 90 00 01 } 		$a_33_1 = {8a 03 8b 95 d4 b1 ff ff 8d 14 92 0f af d6 2b c2 88 } 	condition:
		((#a_13_0  & 1)*1+(#a_33_1  & 1)*6400) >=2
 
}