rule MonitoringTool_Win32_RefogKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 00 77 00 77 00 2e 00 72 00 65 00 66 00 6f 00 67 00 2e 00 63 00 6f 00 6d 00 2f 00 66 00 69 00 6c 00 65 00 73 00 2f 00 69 00 65 00 35 00 2e 00 7a 00 69 00 70 00 } 		$a_01_1 = {41 00 6c 00 6c 00 20 00 43 00 68 00 61 00 74 00 73 00 20 00 77 00 69 00 74 00 68 00 20 00 74 00 68 00 69 00 73 00 20 00 43 00 6f 00 6e 00 74 00 61 00 63 00 74 00 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2) >=6
 
}