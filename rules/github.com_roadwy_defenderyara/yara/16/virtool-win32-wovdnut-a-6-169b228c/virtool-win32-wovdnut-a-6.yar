rule VirTool_Win32_Wovdnut_A__6{
	meta:
		description = "VirTool:Win32/Wovdnut.A!!Wovdnut.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 8d 41 01 8b d0 c6 44 04 40 64 41 8d 41 02 c6 44 04 40 6c 41 8d 41 03 c6 44 04 40 6c 41 8d 41 04 4e 8d 0c 02 88 5c 04 40 8b d3 41 38 19 74 17 } 		$a_03_1 = {ba 05 00 00 20 c7 85 ?? ?? ?? ?? 08 00 00 00 48 8b ce ff 97 ?? ?? ?? ?? 85 c0 0f 85 ?? ?? ?? ?? ff 97 ?? ?? ?? ?? 3d 76 2f 00 00 0f } 		$a_03_2 = {48 81 ec 40 04 00 00 48 8b da 48 8b f1 48 8b 91 ?? ?? ?? ?? 41 b8 00 30 00 00 33 c9 48 8d 14 55 02 00 00 00 44 8d 49 04 ff 56 48 4c 8b f0 48 85 c0 0f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}