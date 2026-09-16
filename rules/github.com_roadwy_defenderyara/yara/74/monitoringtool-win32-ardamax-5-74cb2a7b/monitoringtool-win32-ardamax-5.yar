rule MonitoringTool_Win32_Ardamax_5{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {fa ee c2 99 ea 44 7c 06 } 		$a_01_1 = {90 90 8b 45 08 a3 04 f0 00 01 a1 94 dc 00 01 85 c0 74 2e 68 04 01 00 00 ff 75 0c 68 08 f0 00 01 ff d0 a1 9c dc 00 01 85 c0 74 16 6a 00 ff 35 78 dc 00 01 68 0d 2f 00 01 6a 04 ff d0 a3 00 f0 00 01 90 90 } 		$a_01_2 = {be 1a 00 00 80 eb 32 85 c0 7c 34 53 57 e8 23 ff ff ff 59 59 85 c0 75 03 ff 45 f8 } 		$a_01_3 = {90 90 33 c0 ba 38 a1 00 01 39 45 08 75 0b 8b 4d 0c 8b 41 08 8d 51 0c eb 0f 83 7d 08 01 75 18 8b 45 0c 8d 50 14 8b 40 10 d1 e8 40 3d 03 01 00 00 72 05 b8 04 01 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}