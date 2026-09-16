rule MonitoringTool_Win32_PersonalInspector{
	meta:
		description = "MonitoringTool:Win32/PersonalInspector,SIGNATURE_TYPE_PEHSTR_EXT,08 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 4b 65 79 62 6f 61 72 64 48 6f 6f 6b } 		$a_01_1 = {5b 50 52 49 4e 54 53 43 52 45 45 4e 5d } 		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4b 4d 69 4e 54 32 31 5c 50 65 72 73 6f 6e 61 6c 49 6e 73 70 65 63 74 6f 72 } 		$a_01_3 = {5c 69 6e 73 70 65 63 74 6f 72 2e 72 65 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=6
 
}