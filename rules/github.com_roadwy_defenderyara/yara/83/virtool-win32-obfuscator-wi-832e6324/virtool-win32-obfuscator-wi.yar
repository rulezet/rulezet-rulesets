rule VirTool_Win32_Obfuscator_WI{
	meta:
		description = "VirTool:Win32/Obfuscator.WI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc c6 40 01 65 8b 4d fc 51 ff 15 } 		$a_01_1 = {8b 55 08 03 55 f4 8b 02 03 45 f4 8b 4d 08 03 4d f4 89 01 c7 45 fc 7c 00 00 00 8b 55 f4 81 c2 53 57 09 00 89 55 f8 c7 45 fc 7c 00 00 00 8b 45 08 03 45 f4 8b 08 33 4d f8 8b 55 08 03 55 f4 89 0a eb } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}