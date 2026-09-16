rule MonitoringTool_Win32_ActiveKeyLogger{
	meta:
		description = "MonitoringTool:Win32/ActiveKeyLogger,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 64 76 61 6e 63 65 64 20 49 6e 76 69 73 69 62 6c 65 20 4b 65 79 6c 6f 67 67 65 72 20 28 4b 65 79 73 74 72 6f 6b 65 73 20 54 79 70 65 64 29 } 		$a_03_1 = {54 69 6d 65 3a [0-10] 57 69 6e 64 6f 77 20 54 69 74 6c 65 3a [0-10] 4b 65 79 73 74 72 6f 6b 65 73 3a } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}