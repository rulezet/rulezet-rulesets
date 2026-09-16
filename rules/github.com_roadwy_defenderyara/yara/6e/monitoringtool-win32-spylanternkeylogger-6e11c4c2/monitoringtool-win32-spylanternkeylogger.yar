rule MonitoringTool_Win32_SpyLanternKeylogger{
	meta:
		description = "MonitoringTool:Win32/SpyLanternKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6f 67 20 46 69 6c 65 73 20 28 2a 2e 6c 74 72 29 } 		$a_01_1 = {69 00 73 00 5f 00 6c 00 6f 00 63 00 61 00 6c 00 73 00 70 00 79 00 } 		$a_01_2 = {53 70 79 64 65 78 2c 20 49 6e 63 2e } 		$a_01_3 = {72 65 70 6f 72 74 5f 6b 65 79 5f 62 6f 74 74 6f 6d 2e 74 65 6d 70 6c } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}