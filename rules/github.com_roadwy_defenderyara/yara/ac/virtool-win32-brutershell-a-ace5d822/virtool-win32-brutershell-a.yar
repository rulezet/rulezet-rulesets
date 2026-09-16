rule VirTool_Win32_BruterShell_A{
	meta:
		description = "VirTool:Win32/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ba 23 52 87 a8 4c 89 e1 48 89 84 ?? ?? ?? ?? ?? e8 } 		$a_01_1 = {ba a4 83 d1 35 48 89 d9 e8 } 		$a_01_2 = {41 bd 6c 6c 00 00 41 54 49 89 d4 ba 77 69 00 00 57 bf 6c 6c 00 00 56 be 79 70 00 00 53 44 89 c3 41 b8 63 72 00 00 } 		$a_01_3 = {41 b9 74 2e 00 00 41 ba 32 2e 00 00 41 bb 6e 69 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}