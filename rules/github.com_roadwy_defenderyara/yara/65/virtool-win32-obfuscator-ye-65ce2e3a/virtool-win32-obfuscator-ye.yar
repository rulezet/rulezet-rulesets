rule VirTool_Win32_Obfuscator_YE{
	meta:
		description = "VirTool:Win32/Obfuscator.YE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 0c 01 ff 45 fc 8b 55 fc 88 08 8b 4d 18 40 3b 51 50 72 e9 8b 4b 3c 03 cb 8b 81 a0 00 00 00 } 		$a_01_1 = {33 d2 6a 5a 59 f7 f1 8b 45 f8 28 14 38 40 89 45 f8 3b 45 f4 72 ea } 		$a_01_2 = {8d 0c 10 8d 34 02 8a d9 8b c2 c1 e8 04 24 03 80 e3 1f f6 eb 80 e1 03 f6 e9 b1 fe 2a c8 00 0c 3e ff 45 ec eb c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}