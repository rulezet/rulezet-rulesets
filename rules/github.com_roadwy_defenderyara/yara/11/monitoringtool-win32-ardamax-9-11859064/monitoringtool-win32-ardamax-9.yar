rule MonitoringTool_Win32_Ardamax_9{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,04 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 43 50 61 73 73 77 6f 72 64 45 6e 74 65 72 44 6c 67 40 40 } 		$a_01_1 = {fa ee c2 99 ea 44 7c 06 } 		$a_03_2 = {ff 76 04 ff 36 ff 75 08 e8 ?? ?? ?? ?? 83 c4 0c ff 76 04 8b ce ff 75 08 e8 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 5e 5d c2 04 00 } 		$a_01_3 = {90 90 8b 7d 0c 8b 4d 08 8d 45 fc 50 be 9d 00 00 00 56 57 e8 d2 fe ff ff 85 c0 7c 1e 39 75 fc 75 19 ff 37 e8 e9 fe ff ff 59 3b 47 04 75 0c 57 e8 1e ff ff ff 33 c0 59 40 eb 0a } 		$a_01_4 = {90 90 33 d2 33 f6 39 55 0c 7e 19 83 fa 04 72 02 33 d2 8b 45 08 8a 4c 17 08 03 c6 30 08 42 46 3b 75 0c 7c e7 90 90 } 	condition:
		((#a_01_0  & 1)*-100+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}