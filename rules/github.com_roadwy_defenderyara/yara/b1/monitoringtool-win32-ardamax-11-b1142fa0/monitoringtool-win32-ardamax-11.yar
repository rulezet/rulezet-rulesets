rule MonitoringTool_Win32_Ardamax_11{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {fa ee c2 99 ea 44 7c 06 } 		$a_01_1 = {90 90 33 c9 33 f6 39 4d 10 7e 1b 83 f9 0b 7c 02 33 c9 8b 45 0c 8b 55 08 8a 14 11 03 c6 30 10 41 46 3b 75 10 7c e5 90 90 } 		$a_01_2 = {8d 44 00 01 85 c0 7e 1d 8b d0 56 33 c9 8b 45 08 8d 04 48 be 34 92 00 00 66 31 30 41 83 f9 32 7c ec 4a 75 e7 5e 5d c3 } 		$a_03_3 = {46 46 50 66 8b 46 44 66 03 85 ?? ?? ff ff 0f b7 c0 50 53 ff 15 ?? ?? ?? ?? 89 85 e4 fd ff ff 3b c3 0f 84 ?? ?? 00 00 50 53 ff 15 ?? ?? ?? ?? 3b c3 0f 84 cb 01 00 00 50 ff 15 ?? ?? ?? ?? 89 85 ?? ?? ff ff 3b c3 0f 84 ?? ?? 00 00 ff b5 ?? ?? ff ff 53 ff 15 ?? ?? ?? ?? 03 f8 89 85 ?? ?? ff ff 57 39 9d ?? ?? ff ff 74 0e ff b5 ?? ?? ff ff e8 ?? ?? ?? ?? 59 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}