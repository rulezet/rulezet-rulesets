rule VirTool_Win32_Wovdnut_A__5{
	meta:
		description = "VirTool:Win32/Wovdnut.A!!Wovdnut.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 8d 41 01 8b d0 c6 44 04 40 64 41 8d 41 02 c6 44 04 40 6c 41 8d 41 03 c6 44 04 40 6c 41 8d 41 04 4e 8d 0c 02 88 5c 04 40 8b d3 41 38 19 74 } 		$a_03_1 = {ba 05 00 00 20 48 8b cb ff ?? ?? ?? 00 00 85 c0 74 ?? 48 8b 16 48 85 d2 74 ?? 33 c9 45 8d ?? ?? 04 41 b8 00 30 00 00 ff } 		$a_01_2 = {04 b8 00 32 e0 84 44 8b e3 89 5c 24 } 		$a_01_3 = {8b 13 bd 04 00 00 00 44 8b cd 33 c9 41 b8 00 30 00 00 41 ff d4 48 8b f0 48 85 c0 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}