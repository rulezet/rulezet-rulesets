rule VirTool_Win32_BruterShell_A_5{
	meta:
		description = "VirTool:Win32/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 bd 6c 6c 00 00 41 54 49 89 d4 ba 77 69 00 00 57 bf 6c 6c 00 00 56 be 79 70 00 00 53 44 89 c3 41 b8 63 72 00 00 } 		$a_01_1 = {41 b9 74 2e 00 00 41 ba 32 2e 00 00 41 bb 6e 69 00 00 } 		$a_03_2 = {80 79 01 8b 75 ?? 80 79 02 d1 75 ?? 41 80 f8 b8 75 ?? 80 79 06 00 75 } 		$a_03_3 = {48 83 c1 01 48 39 c8 74 ?? 80 39 0f 75 ?? 80 79 01 05 75 ?? 80 79 02 c3 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}