rule MonitoringTool_Win32_ActualSpy_3{
	meta:
		description = "MonitoringTool:Win32/ActualSpy,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 6b 64 6c 6c 2e 64 6c 6c 00 52 65 6d 6f 76 65 41 70 70 48 6f 6f 6b } 		$a_01_1 = {66 72 6f 6d 20 68 6f 6f 6b 64 6c 6c 2e 64 6c 6c } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 42 6f 72 6c 61 6e 64 5c 4c 6f 63 61 6c 65 73 } 		$a_01_3 = {53 65 74 4b 65 79 62 6f 61 72 64 48 6f 6f 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}