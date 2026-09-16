rule MonitoringTool_Win64_RefogKeylogger_2{
	meta:
		description = "MonitoringTool:Win64/RefogKeylogger,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7a 3a 5c 50 72 6f 6a 65 63 74 73 5c 52 65 6c 65 61 73 65 52 65 70 6f 73 69 74 6f 72 79 5c 4d 6f 6e 69 74 6f 72 50 72 6f 6a 65 63 74 5c 44 65 6c 70 68 69 5c 44 69 73 74 72 5c 52 65 66 6f 67 4d 6f 6e 69 74 6f 72 5c 4d 70 6b 36 34 2e 70 64 62 } 		$a_01_1 = {4d 00 55 00 54 00 45 00 58 00 5f 00 50 00 52 00 4f 00 47 00 52 00 41 00 4d 00 4d 00 5f 00 52 00 55 00 4e 00 4e 00 49 00 4e 00 47 00 3a 00 4d 00 50 00 4b 00 36 00 34 00 5f 00 4c 00 4f 00 41 00 44 00 45 00 52 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}