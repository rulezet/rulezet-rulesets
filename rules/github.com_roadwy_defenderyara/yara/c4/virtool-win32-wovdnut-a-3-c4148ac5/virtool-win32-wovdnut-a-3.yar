rule VirTool_Win32_Wovdnut_A__3{
	meta:
		description = "VirTool:Win32/Wovdnut.A!!Wovdnut.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 8d 41 01 8b d0 c6 44 04 40 64 41 8d 41 02 c6 44 04 40 6c 41 8d 41 03 c6 44 04 40 6c 41 8d 41 04 4e 8d 0c 02 88 5c 04 40 8b d3 41 38 19 74 } 		$a_01_1 = {8b 4f 50 b8 00 30 00 00 56 6a 40 50 89 44 24 1c b8 00 10 00 00 03 c8 51 6a 00 ff 53 } 		$a_03_2 = {68 05 00 00 20 55 89 ?? 89 ?? 04 ff ?? ?? 00 00 00 85 c0 74 33 8b 03 0b 43 04 74 2c 6a 04 68 00 30 00 00 ff 33 ?? ff } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}