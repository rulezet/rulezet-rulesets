rule VirTool_Win32_BruterShell_A_2{
	meta:
		description = "VirTool:Win32/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 79 01 8b 75 ?? 80 79 02 d1 75 ?? 41 80 f8 b8 75 ?? 80 79 06 00 75 } 		$a_01_1 = {48 b8 61 64 76 61 70 69 33 32 4c 89 e9 48 89 44 24 60 e8 } 		$a_01_2 = {4d 8b 04 24 ba c0 21 1d be 4c 89 e1 e8 } 		$a_03_3 = {48 c7 c2 ff ff ff ff c7 44 24 ?? 04 00 00 00 c7 44 24 ?? 00 30 00 00 [0-10] e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}