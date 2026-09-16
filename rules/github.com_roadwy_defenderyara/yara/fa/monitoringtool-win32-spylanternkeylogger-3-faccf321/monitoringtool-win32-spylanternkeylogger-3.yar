rule MonitoringTool_Win32_SpyLanternKeylogger_3{
	meta:
		description = "MonitoringTool:Win32/SpyLanternKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {25 73 5c 50 49 50 45 5c 25 73 5f 63 74 72 6c 00 [0-10] 5c 5c 25 73 5c 50 49 50 45 5c 25 73 5f 64 61 74 61 25 75 00 } 		$a_02_1 = {53 70 79 20 4c 61 6e 74 65 72 6e 20 4b 65 79 6c 6f 67 67 65 72 00 [0-10] 25 73 5f 68 6b 6d 61 70 00 [0-10] 25 73 5c 64 62 00 00 } 		$a_02_2 = {53 70 79 20 4c 61 6e 74 65 72 6e 20 4b 65 79 6c 6f 67 67 65 72 5c [0-35] 3c 43 6f 6e 66 69 67 75 72 61 74 69 6f 6e 3e [0-20] 3c 55 6e 69 71 49 44 20 6e 61 6d 65 3d 22 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}