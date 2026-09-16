rule MonitoringTool_Win32_FamilyKeylogger{
	meta:
		description = "MonitoringTool:Win32/FamilyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 46 61 6d 69 6c 79 20 4b 65 79 6c 6f 67 67 65 72 20 34 5c 46 61 6d 69 6c 79 20 4b 65 79 6c 6f 67 67 65 72 2e 6c 6e 6b } 		$a_01_1 = {6d 61 69 6c 74 6f 3a 73 75 70 6f 72 74 40 73 70 79 61 72 73 65 6e 61 6c 2e 63 6f 6d 3f 73 75 62 6a 65 63 74 3d 46 4b 4c 34 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*5) >=8
 
}