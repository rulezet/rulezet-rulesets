rule VirTool_Win32_Wovdnut_A_sms_5{
	meta:
		description = "VirTool:Win32/Wovdnut.A!sms,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 b9 04 00 00 00 41 b8 00 30 00 00 ba a4 0f 00 00 b9 00 00 00 00 ff } 		$a_03_1 = {83 c0 01 89 c0 c6 44 05 ?? 64 8b 45 ?? 83 c0 02 89 c0 c6 44 05 ?? 6c 8b 45 ?? 83 c0 03 89 c0 c6 44 05 ?? 6c 8b 45 ?? 83 c0 04 89 c0 c6 44 05 ?? 00 } 		$a_01_2 = {ff d0 3d 76 2f 00 00 0f 85 } 		$a_03_3 = {6e 74 64 6c 75 [0-10] 20 20 20 20 [0-08] 6c 2e 64 6c 74 } 		$a_01_4 = {0f b7 00 66 3d 5a 77 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}