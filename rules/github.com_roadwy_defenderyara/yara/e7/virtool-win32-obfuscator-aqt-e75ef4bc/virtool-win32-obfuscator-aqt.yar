rule VirTool_Win32_Obfuscator_AQT{
	meta:
		description = "VirTool:Win32/Obfuscator.AQT,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 55 f8 8b 45 f8 83 c0 01 89 45 f4 8b 4d f8 8a 11 88 55 f3 83 45 f8 01 80 7d f3 00 } 		$a_03_1 = {33 d2 f7 75 ec 8b 0d ?? ?? ?? ?? 0f be 14 11 8b 45 08 03 45 fc 0f be 08 33 ca 8b 55 08 03 55 fc 88 0a } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}