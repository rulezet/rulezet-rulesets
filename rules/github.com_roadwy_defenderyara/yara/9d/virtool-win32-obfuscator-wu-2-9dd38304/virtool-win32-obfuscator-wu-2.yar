rule VirTool_Win32_Obfuscator_WU_2{
	meta:
		description = "VirTool:Win32/Obfuscator.WU,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {60 8b 45 08 25 00 ff ff ff 05 00 01 00 00 2d 00 01 00 00 66 81 38 4d 5a 75 f4 8b 48 3c 81 f9 00 10 00 00 77 e9 03 c8 81 39 50 45 00 00 75 df 89 45 fc 61 8b 45 fc 5f 5e 5b c9 c2 04 00 } 		$a_03_1 = {8b 48 20 03 0d ?? ?? ?? ?? 89 4d cc 8b 48 24 03 0d ?? ?? ?? ?? 89 4d b0 c7 45 c0 00 00 00 00 56 8b 7d c0 c1 e7 02 03 7d cc 8b 3f 03 3d ?? ?? ?? ?? 8b 4d b8 f3 a6 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}