rule VirTool_Win32_Wovdnut_A_sms_4{
	meta:
		description = "VirTool:Win32/Wovdnut.A!sms,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 8d 41 01 8b d0 c6 44 04 40 64 41 8d 41 02 c6 44 04 40 6c 41 8d 41 03 c6 44 04 40 6c 41 8d 41 04 4e 8d 0c 02 88 5c 04 40 8b d3 41 38 19 74 17 } 		$a_03_1 = {6a 40 b8 00 30 00 00 b9 00 10 00 00 50 89 44 24 ?? 8b 47 50 03 c1 50 ?? ff } 		$a_03_2 = {68 05 00 00 20 55 89 ?? 89 ?? 04 ff ?? ?? 00 00 00 85 c0 74 33 8b 03 0b 43 04 74 2c 6a 04 68 00 30 00 00 ff 33 ?? ff } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}