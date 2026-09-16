rule VirTool_Win32_Obfuscator_WU{
	meta:
		description = "VirTool:Win32/Obfuscator.WU,SIGNATURE_TYPE_PEHSTR_EXT,64 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 75 18 8b 86 2c 11 00 00 0b 86 38 11 00 00 } 		$a_03_1 = {39 9e 10 11 00 00 75 11 ff b6 08 11 00 00 57 ff 75 18 e8 ?? ?? ff ff } 		$a_03_2 = {8b 48 24 03 0d ?? ?? ?? ?? 89 4d c0 c7 45 cc 00 00 00 00 56 8b 7d cc c1 e7 02 03 7d d8 8b 3f 03 3d ?? ?? ?? ?? 8b 4d c4 f3 a6 74 07 5e 83 45 cc 01 eb e0 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}