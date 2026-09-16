rule MonitoringTool_Win32_ActualSpy_2{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 4b 65 79 62 6f 61 72 64 48 6f 6f 6b } 		$a_00_1 = {75 23 f7 c3 00 00 00 80 75 1b 83 ff 10 75 16 56 6a 01 68 13 2b 00 00 } 		$a_00_2 = {61 70 70 68 6f 6f 6b } 		$a_00_3 = {6d 6f 75 73 65 68 6f 6f 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}