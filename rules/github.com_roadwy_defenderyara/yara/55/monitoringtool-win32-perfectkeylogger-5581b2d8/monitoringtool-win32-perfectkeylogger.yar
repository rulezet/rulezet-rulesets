rule MonitoringTool_Win32_PerfectKeylogger{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 69 5f 62 70 6b 5f 74 72 69 61 6c 2e 65 78 65 } 		$a_01_1 = {63 6f 6e 6e 65 63 74 65 64 20 74 6f 20 49 6e 74 65 72 6e 65 74 } 		$a_01_2 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 50 00 65 00 72 00 66 00 65 00 63 00 74 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}