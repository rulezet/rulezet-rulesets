rule MonitoringTool_Win32_PerfectKeylogger_4{
	meta:
		description = "MonitoringTool:Win32/PerfectKeylogger,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } 		$a_01_1 = {45 6e 61 62 6c 65 53 70 65 63 69 61 6c 4b 65 79 73 4c 6f 67 67 69 6e 67 } 		$a_01_2 = {45 6e 61 62 6c 65 4e 54 49 6e 76 69 73 69 62 6c 65 } 		$a_01_3 = {77 62 2e 64 6c 6c 00 00 68 6b 2e 64 6c 6c } 		$a_01_4 = {74 69 74 6c 65 73 2e 64 61 74 00 61 70 70 73 2e 64 61 74 } 		$a_01_5 = {00 70 6b 2e 62 69 6e 00 00 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=11
 
}