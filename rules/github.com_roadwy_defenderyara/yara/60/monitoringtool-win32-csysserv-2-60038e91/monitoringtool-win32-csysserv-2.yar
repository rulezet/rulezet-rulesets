rule MonitoringTool_Win32_Csysserv_2{
	meta:
		description = "MonitoringTool:Win32/Csysserv,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 47 6c 6f 62 61 6c 5c 4b 65 79 4c 6f 67 4d 74 78 00 00 } 		$a_01_1 = {4b 65 79 50 72 6f 63 00 54 68 65 48 6f 6f 6b 58 50 2e 64 6c 6c } 		$a_01_2 = {53 65 74 56 61 6c 75 65 73 4d 6f 75 73 65 } 		$a_01_3 = {53 65 74 56 61 6c 75 65 73 4b 65 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}