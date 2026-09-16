rule MonitoringTool_Win32_SpyAgent{
	meta:
		description = "MonitoringTool:Win32/SpyAgent,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 70 79 41 67 65 6e 74 5f 48 57 4e 44 33 32 } 		$a_01_1 = {25 73 5c 73 61 6f 70 74 73 2e 64 61 74 } 		$a_01_2 = {53 70 79 74 65 63 68 20 53 70 79 41 67 65 6e 74 } 		$a_01_3 = {43 6c 69 65 6e 74 20 68 6f 6f 6b 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}