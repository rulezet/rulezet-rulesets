rule MonitoringTool_Win32_FreeQuickKeylogger{
	meta:
		description = "MonitoringTool:Win32/FreeQuickKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 64 65 53 74 65 70 20 46 72 65 65 20 4c 69 63 65 6e 73 65 20 41 67 72 65 65 6d 65 6e 74 } 		$a_01_1 = {46 72 65 65 20 51 75 69 63 6b 20 4b 65 79 6c 6f 67 67 65 72 } 		$a_01_2 = {71 75 69 63 6b 5f 65 6e 67 69 6e 65 2e 65 78 65 00 71 6b 5f 75 73 65 72 5f 67 75 69 64 65 2e 68 74 6d 00 51 75 69 63 6b 41 70 70 49 6e 69 74 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}