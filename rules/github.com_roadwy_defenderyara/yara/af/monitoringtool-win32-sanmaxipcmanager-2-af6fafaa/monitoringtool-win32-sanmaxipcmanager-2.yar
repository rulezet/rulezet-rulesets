rule MonitoringTool_Win32_SanmaxiPCManager_2{
	meta:
		description = "MonitoringTool:Win32/SanmaxiPCManager,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 53 00 61 00 6e 00 6d 00 61 00 78 00 69 00 5c 00 4b 00 4c 00 6f 00 67 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 } 		$a_01_1 = {53 61 6e 6d 61 78 69 20 50 43 20 4d 61 6e 61 67 65 72 20 69 73 20 73 74 69 6c 6c 20 72 65 63 6f 72 64 69 6e 67 20 6b 65 79 20 73 74 72 6f 6b 65 73 } 		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6b 65 79 2d 6c 6f 67 67 65 72 2e 77 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}