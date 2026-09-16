rule MonitoringTool_Win32_MessengerLog_2{
	meta:
		description = "MonitoringTool:Win32/MessengerLog,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 61 74 20 4c 6f 67 20 66 72 6f 6d 20 4d 65 73 73 65 6e 67 65 72 4c 6f 67 20 33 36 30 } 		$a_01_1 = {28 4c 6f 67 55 70 6c 6f 61 64 65 72 3a 3a 55 70 6c 6f 61 64 4c 6f 67 29 20 43 68 61 74 20 6c 6f 67 20 75 70 6c 6f 61 64 20 66 61 69 6c 65 64 20 76 69 61 20 46 54 50 2e } 		$a_01_2 = {28 43 68 61 74 4c 6f 67 32 3a 3a 57 72 69 74 65 4c 6f 67 29 20 43 61 6e 20 6e 6f 74 20 7a 69 70 20 66 69 6c 65 20 25 73 3a 20 25 64 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}