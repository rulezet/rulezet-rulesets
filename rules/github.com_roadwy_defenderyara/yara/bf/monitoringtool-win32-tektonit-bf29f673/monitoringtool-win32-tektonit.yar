rule MonitoringTool_Win32_TektonIt{
	meta:
		description = "MonitoringTool:Win32/TektonIt,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {2d 64 20 25 61 70 70 64 61 74 61 25 5c 57 69 6e 64 6f 77 73 5c 63 6f 6e 74 72 6f 6c } 		$a_01_1 = {72 00 75 00 6e 00 2e 00 62 00 61 00 74 00 } 		$a_01_2 = {62 00 32 00 62 00 32 00 65 00 74 00 65 00 6d 00 70 00 66 00 69 00 6c 00 65 00 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}