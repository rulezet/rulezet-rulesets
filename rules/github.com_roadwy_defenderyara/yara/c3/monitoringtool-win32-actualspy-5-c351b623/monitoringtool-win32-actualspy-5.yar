rule MonitoringTool_Win32_ActualSpy_5{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 09 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 4d 4d 46 } 		$a_00_1 = {41 70 70 48 6f 6f 6b } 		$a_00_2 = {44 65 73 74 72 6f 79 48 6f 6f 6b } 		$a_00_3 = {4b 65 79 62 6f 61 72 64 48 6f 6f 6b } 		$a_00_4 = {4d 6f 75 73 65 48 6f 6f 6b } 		$a_00_5 = {53 68 69 66 74 43 61 70 73 48 6f 6f 6b } 		$a_00_6 = {57 69 6e 64 6f 77 48 6f 6f 6b } 		$a_00_7 = {6e 65 77 6e 65 77 } 		$a_01_8 = {74 2f 6a 38 6a 00 6a 00 68 1f 00 0f 00 } 	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_01_8  & 1)*3) >=10
 
}