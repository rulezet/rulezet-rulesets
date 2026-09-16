rule MonitoringTool_Win32_PCAgent_2{
	meta:
		description = "MonitoringTool:Win32/PCAgent,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 43 20 4d 6f 6e 69 74 6f 72 69 6e 67 20 53 6f 66 74 77 61 72 65 } 		$a_01_1 = {62 6c 75 65 2d 73 65 72 69 65 73 2e 64 65 } 		$a_01_2 = {4f 70 65 6e 20 61 6e 64 20 76 69 65 77 20 74 68 65 20 6c 6f 67 2d 66 69 6c 65 73 } 		$a_01_3 = {50 63 61 43 68 65 63 6b 56 65 72 73 69 6f 6e 43 68 6b 56 41 76 61 69 6c 61 62 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}