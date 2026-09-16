rule VirTool_Win32_Obfuscator_QN_2{
	meta:
		description = "VirTool:Win32/Obfuscator.QN,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 06 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec f6 40 0c 40 74 06 83 78 08 00 74 1a 50 ff 75 08 e8 e3 26 00 00 59 59 b9 ff ff 00 00 66 3b c1 75 05 83 0e ff } 		$a_01_1 = {eb 0c 8d 45 e0 50 53 e8 3e 00 00 00 59 59 ff 4d e4 78 07 8b 45 e0 88 18 eb 0c 8d 45 e0 50 53 } 		$a_01_2 = {55 8b ec 83 ec 14 8b 45 0c 89 45 f4 c7 45 f8 00 00 00 00 33 c9 89 4d fc c7 45 f0 00 00 00 00 c7 45 ec 8b 02 00 00 68 00 30 00 00 } 		$a_01_3 = {ff ff eb 02 eb 9a c2 0f 00 } 		$a_01_4 = {30 39 2d 30 61 2d 73 30 39 61 2d 73 64 39 61 39 2d 73 64 2d 61 73 2d 64 2d } 		$a_01_5 = {30 39 2d 30 61 2d 73 34 33 35 35 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}