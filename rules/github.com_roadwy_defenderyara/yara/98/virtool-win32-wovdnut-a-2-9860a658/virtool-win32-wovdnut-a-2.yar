rule VirTool_Win32_Wovdnut_A__2{
	meta:
		description = "VirTool:Win32/Wovdnut.A!!Wovdnut.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 3e 00 75 ?? c7 44 14 29 64 6c 6c 00 42 03 ca 33 d2 38 11 74 ?? 8d 74 } 		$a_03_1 = {6a 40 b8 00 30 00 00 b9 00 10 00 00 50 89 44 24 ?? 8b 47 50 03 c1 50 ?? ff } 		$a_03_2 = {68 05 00 00 20 55 89 ?? 89 ?? 04 ff ?? ?? 00 00 00 85 c0 74 33 8b 03 0b 43 04 74 2c 6a 04 68 00 30 00 00 ff 33 ?? ff } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}