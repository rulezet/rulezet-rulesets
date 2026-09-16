rule MonitoringTool_Win32_SpyLanternKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/SpyLanternKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 6b 33 34 35 33 34 32 33 34 4d 45 44 52 45 57 73 64 66 77 65 4c 61 75 6e 63 68 4d 75 74 65 78 00 } 		$a_01_1 = {67 61 74 65 77 61 79 2e 6d 65 73 73 65 6e 67 65 72 2e 68 6f 74 6d 61 69 6c 2e 63 6f 6d } 		$a_01_2 = {72 6b 5f 63 74 72 6c 5f 6e 6f 69 64 6c 65 33 32 } 		$a_01_3 = {5f 5f 49 54 53 4e 4f 54 52 4f 4f 4d 5f 5f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}