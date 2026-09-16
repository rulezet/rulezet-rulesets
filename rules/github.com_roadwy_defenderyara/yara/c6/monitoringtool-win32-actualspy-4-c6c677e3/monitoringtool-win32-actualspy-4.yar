rule MonitoringTool_Win32_ActualSpy_4{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 6f 66 74 77 61 72 65 5c 41 4b 50 72 6f 67 72 61 6d 5c 4b 65 79 6c 6f 67 67 65 72 } 		$a_01_1 = {73 70 79 5f 6f 6e 6c 79 5f 63 68 61 72 } 		$a_01_2 = {74 6f 20 73 68 6f 77 20 41 63 74 75 61 6c 20 4b 65 79 6c 6f 67 67 65 72 } 		$a_01_3 = {41 63 74 75 61 6c 20 4b 65 79 6c 6f 67 67 65 72 5f 69 73 } 		$a_01_4 = {41 63 74 75 61 6c 20 53 70 79 20 2d 20 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}