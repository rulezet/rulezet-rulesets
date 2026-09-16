rule MonitoringTool_Win32_ActualSpy{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 68 70 72 6f 67 2e 64 6c 6c 00 48 69 64 65 [0-01] 50 72 6f 63 65 73 73 00 53 68 6f 77 50 72 6f 63 65 73 73 } 		$a_00_1 = {6e 74 68 69 64 65 66 69 6c 65 6d 61 70 70 69 6e 67 } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}