rule MonitoringTool_Win32_AdvancedKeylogger{
	meta:
		description = "MonitoringTool:Win32/AdvancedKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 32 43 32 45 46 35 46 2d 45 32 30 30 2d 34 31 37 65 2d 41 45 32 30 2d 42 31 42 32 34 31 45 36 42 45 33 39 } 		$a_01_1 = {41 72 65 79 6f 75 53 75 72 65 44 65 6c 65 74 65 54 68 69 73 4c 6f 67 } 		$a_01_2 = {53 63 72 65 65 6e 74 73 68 6f 74 50 61 67 65 43 6f 6c } 		$a_01_3 = {2e 63 6f 6d 2f 78 70 61 64 76 61 6e 63 65 64 6b 65 79 6c 6f 67 67 65 72 2f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}