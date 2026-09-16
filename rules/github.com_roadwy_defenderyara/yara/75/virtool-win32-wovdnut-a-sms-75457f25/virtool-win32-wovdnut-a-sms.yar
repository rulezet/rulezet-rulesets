rule VirTool_Win32_Wovdnut_A_sms{
	meta:
		description = "VirTool:Win32/Wovdnut.A!sms,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 3e 00 75 ?? c7 44 14 29 64 6c 6c 00 42 03 ca 33 d2 38 11 74 ?? 8d 74 } 		$a_01_1 = {8b 4f 50 b8 00 30 00 00 56 6a 40 50 89 44 24 1c b8 00 10 00 00 03 c8 51 6a 00 ff 53 3c } 		$a_03_2 = {68 05 00 00 20 55 89 ?? 89 ?? 04 ff ?? ?? 00 00 00 85 c0 74 33 8b 03 0b 43 04 74 2c 6a 04 68 00 30 00 00 ff 33 ?? ff } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}