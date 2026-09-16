rule VirTool_Win64_BruterShell_A{
	meta:
		description = "VirTool:Win64/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {31 c9 ba 26 25 19 3e 49 89 c0 e8 ?? ?? ?? ?? 44 8d 43 01 } 		$a_03_1 = {41 80 f8 4c [0-10] 80 79 01 8b 75 ?? 80 79 02 d1 75 ?? 41 80 f9 b8 75 ?? 80 79 06 00 } 		$a_03_2 = {4c 8b 03 ba bd ca 3b d3 48 89 d9 48 89 84 24 ?? 00 00 00 e8 } 		$a_03_3 = {48 c7 c2 ff ff ff ff c7 44 24 ?? 04 00 00 00 c7 44 24 ?? 00 30 00 00 [0-10] e8 } 		$a_01_4 = {ba b8 0a 4c 53 e8 } 		$a_03_5 = {ba 89 4d 39 8c 48 89 84 24 ?? ?? 00 00 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}