rule MonitoringTool_Win32_RevealerKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/RevealerKeylogger,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {52 00 65 00 76 00 65 00 61 00 6c 00 65 00 72 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 50 00 72 00 6f 00 } 		$a_01_1 = {5f 4c 6f 77 4c 65 76 65 6c 4b 65 79 62 6f 61 72 64 50 72 6f 63 40 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}