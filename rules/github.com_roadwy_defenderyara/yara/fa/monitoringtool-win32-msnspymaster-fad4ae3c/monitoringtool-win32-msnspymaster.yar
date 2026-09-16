rule MonitoringTool_Win32_MsnSpyMaster{
	meta:
		description = "MonitoringTool:Win32/MsnSpyMaster,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 61 70 70 7d 5c 6d 73 6d 61 73 74 65 72 2e 65 78 65 } 		$a_01_1 = {4d 73 6e 20 53 70 79 4d 61 73 74 65 72 } 		$a_01_2 = {53 79 6e 63 73 6f 66 74 20 53 6f 66 74 77 61 72 65 73 20 6f 75 20 73 65 75 73 20 66 6f 72 6e 65 63 65 64 6f 72 65 73 20 72 65 73 70 6f 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}