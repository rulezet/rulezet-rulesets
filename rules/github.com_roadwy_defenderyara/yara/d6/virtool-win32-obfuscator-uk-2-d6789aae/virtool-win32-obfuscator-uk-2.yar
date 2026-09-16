rule VirTool_Win32_Obfuscator_UK_2{
	meta:
		description = "VirTool:Win32/Obfuscator.UK,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b f8 89 45 e8 83 c0 36 89 45 f0 83 c0 0c 89 44 24 04 b9 00 ?? 00 00 51 c1 e9 02 } 		$a_01_1 = {8d 77 0c 81 c6 b0 02 00 00 8b 4f 04 81 e9 b0 02 00 00 83 e9 42 8b fe c1 e9 04 } 		$a_01_2 = {8a 46 0a 8a 67 0e 32 c2 32 e2 88 66 0a 88 47 0e 83 c7 10 83 c6 10 } 		$a_01_3 = {b8 a7 50 36 79 90 ba a9 c8 d7 80 8b 4d 10 47 39 07 74 03 49 75 f8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}