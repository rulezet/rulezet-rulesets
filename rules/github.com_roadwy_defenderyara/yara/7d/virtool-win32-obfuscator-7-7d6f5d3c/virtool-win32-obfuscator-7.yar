rule VirTool_Win32_Obfuscator_7{
	meta:
		description = "VirTool:Win32/Obfuscator,SIGNATURE_TYPE_PEHSTR_EXT,64 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {b8 4d 5a 00 00 66 39 07 75 17 8b 77 3c 81 fe 00 04 00 00 89 75 f8 7f 09 81 3c 3e 50 45 00 00 } 		$a_01_1 = {6a 40 68 00 30 00 00 52 6a 00 ff d3 } 		$a_03_2 = {68 34 01 00 00 68 ?? ?? ?? 00 51 89 5d f4 ff d7 } 		$a_03_3 = {8d 46 01 83 f8 3e 88 9e ?? ?? ?? 00 7d 19 ba 3e 00 00 00 2b d0 52 8d 88 ?? ?? ?? 00 6a 01 51 e8 ?? ?? ?? ?? 83 c4 0c } 		$a_03_4 = {00 40 49 3b c6 7c f2 90 09 07 00 8a 11 88 90 90 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}