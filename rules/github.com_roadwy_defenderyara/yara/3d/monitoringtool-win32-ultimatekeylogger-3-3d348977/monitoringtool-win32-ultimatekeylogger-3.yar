rule MonitoringTool_Win32_UltimateKeylogger_3{
	meta:
		description = "MonitoringTool:Win32/UltimateKeylogger,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 75 6c 6b 6c 66 65 6d 6f 6e 2e 64 6c 6c } 		$a_01_1 = {4b 65 79 48 6f 6f 6b } 		$a_01_2 = {5c 53 69 6c 65 6e 74 4b 65 79 } 		$a_01_3 = {00 75 6b 66 72 65 65 2e 63 66 67 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}