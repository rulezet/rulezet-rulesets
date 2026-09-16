rule VirTool_Win32_Obfuscator_6{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {85 c9 8b c1 74 03 8d 04 09 8b 7d fc 8d 04 41 81 } 		$a_01_1 = {8d 14 31 85 d2 74 02 33 f6 03 c1 8b 7d 0c 03 c8 } 		$a_01_2 = {d0 8b c2 81 ef d2 02 96 49 f7 d8 89 7d fc 74 02 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}