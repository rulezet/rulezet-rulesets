rule VirTool_Win32_BruterShell_A_4{
	meta:
		description = "VirTool:Win32/BruterShell.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {80 78 05 e8 75 ?? 80 78 06 03 75 ?? 80 78 0d 8b 75 ?? 80 78 0e d4 75 ?? 0f b6 50 02 } 		$a_01_1 = {c7 44 24 04 89 4d 39 8c 89 44 24 08 e8 } 		$a_03_2 = {89 14 24 c7 44 24 ?? 50 4f 53 54 c6 44 24 ?? 00 c7 44 24 ?? 7b 22 61 72 c7 44 24 ?? 63 68 22 3a } 		$a_03_3 = {c7 44 24 04 aa fc 0d 7c [0-80] c7 44 24 04 bd ca 3b d3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}