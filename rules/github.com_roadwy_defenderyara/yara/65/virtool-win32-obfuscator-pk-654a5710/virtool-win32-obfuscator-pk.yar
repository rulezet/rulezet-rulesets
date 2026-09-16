rule VirTool_Win32_Obfuscator_PK{
	meta:
		description = "VirTool:Win32/Obfuscator.PK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 4d f4 c7 45 fc 00 00 00 00 eb 09 8b 55 fc 83 c2 08 89 55 fc 81 7d fc ?? ?? 00 00 0f 83 } 		$a_01_1 = {8b 4d f4 03 c8 89 4d f4 8b 55 f8 03 55 fc 8b 02 03 45 ec 8b 4d f8 03 4d fc 89 01 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}