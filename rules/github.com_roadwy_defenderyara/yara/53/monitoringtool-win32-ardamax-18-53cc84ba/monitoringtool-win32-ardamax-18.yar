rule MonitoringTool_Win32_Ardamax_18{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 00 72 00 64 00 61 00 6d 00 61 00 78 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 } 		$a_01_1 = {41 00 4b 00 4c 00 4d 00 57 00 00 00 } 		$a_01_2 = {6d 00 73 00 6e 00 6d 00 73 00 67 00 72 00 2e 00 65 00 78 00 65 00 00 00 } 		$a_01_3 = {00 22 20 61 6c 74 3d 22 22 2f 3e 3c 2f 70 3e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}