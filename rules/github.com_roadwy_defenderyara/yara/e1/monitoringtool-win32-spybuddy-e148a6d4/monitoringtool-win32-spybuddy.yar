rule MonitoringTool_Win32_SpyBuddy{
	meta:
		description = "MonitoringTool:Win32/SpyBuddy,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 70 79 42 75 64 64 79 20 53 65 73 73 69 6f 6e 20 52 65 70 6f 72 74 } 		$a_01_1 = {62 79 20 53 70 79 42 75 64 64 79 21 } 		$a_01_2 = {42 65 20 4d 6f 6e 69 74 6f 72 65 64 } 		$a_01_3 = {6b 65 79 77 6f 72 64 20 6f 72 20 70 68 72 61 73 65 } 		$a_01_4 = {5f 68 6f 6f 6b 5d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}