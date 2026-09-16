rule MonitoringTool_Win32_MessengerLog{
	meta:
		description = "MonitoringTool:Win32/MessengerLog,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 22 00 25 00 73 00 6d 00 6c 00 33 00 36 00 30 00 2e 00 64 00 6c 00 6c 00 22 00 20 00 53 00 74 00 61 00 72 00 74 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 } 		$a_01_1 = {4d 4c 33 36 30 53 72 76 2e 49 53 65 72 76 43 6f 6e 74 72 6f 6c 6c 65 72 20 3d 20 73 20 27 49 53 65 72 76 43 6f 6e 74 72 6f 6c 6c 65 72 20 43 6c 61 73 73 27 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}