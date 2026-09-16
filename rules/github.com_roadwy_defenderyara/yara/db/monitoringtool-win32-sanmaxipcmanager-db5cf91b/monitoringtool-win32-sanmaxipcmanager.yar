rule MonitoringTool_Win32_SanmaxiPCManager{
	meta:
		description = "MonitoringTool:Win32/SanmaxiPCManager,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 61 6e 6d 61 78 69 20 50 43 20 4d 61 6e 61 67 65 72 20 2d 20 54 65 78 74 20 4c 6f 67 20 52 65 70 6f 72 74 } 		$a_01_1 = {41 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 64 65 6c 65 74 65 20 61 6c 6c 20 63 61 70 74 75 72 65 64 20 55 53 42 2f 73 79 73 74 65 6d 20 6c 6f 67 73 20 70 65 72 6d 61 6e 65 6e 74 6c 79 2e } 		$a_01_2 = {53 63 72 65 65 6e 73 68 6f 74 20 72 65 70 6f 72 74 2e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}