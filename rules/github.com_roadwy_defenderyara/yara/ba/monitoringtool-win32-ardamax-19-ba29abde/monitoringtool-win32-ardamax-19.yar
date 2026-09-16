rule MonitoringTool_Win32_Ardamax_19{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 00 3a 00 5c 00 41 00 4b 00 56 00 2e 00 30 00 30 00 30 00 } 		$a_01_1 = {41 00 72 00 64 00 61 00 6d 00 61 00 78 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } 		$a_01_2 = {25 00 62 00 5f 00 25 00 64 00 5f 00 25 00 59 00 5f 00 5f 00 25 00 48 00 5f 00 25 00 4d 00 5f 00 25 00 53 00 2e 00 6a 00 70 00 67 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}