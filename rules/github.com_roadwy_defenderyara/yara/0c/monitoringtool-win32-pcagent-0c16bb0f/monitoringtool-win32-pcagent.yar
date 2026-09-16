rule MonitoringTool_Win32_PCAgent{
	meta:
		description = "MonitoringTool:Win32/PCAgent,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 6f 6e 50 77 57 61 74 63 68 } 		$a_01_1 = {50 43 41 5f 53 45 54 54 49 4e 47 53 } 		$a_01_2 = {48 6f 6f 6b 57 61 74 63 68 2e 47 65 74 4d 6f 75 73 65 4d 65 73 73 61 67 65 } 		$a_01_3 = {20 50 43 41 20 4d 61 69 6c 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}