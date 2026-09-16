rule MonitoringTool_Win32_Actmon_2{
	meta:
		description = "MonitoringTool:Win32/Actmon,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {77 73 6b 72 6e 6c 61 64 2e 64 6c 6c 00 3f 48 6f 6f 6b 5f 53 65 74 32 40 40 59 41 48 48 48 40 5a 00 3f 48 6f 6f 6b 5f 53 65 74 40 40 59 41 48 48 48 40 5a 00 3f 48 6f 6f 6b 5f 53 74 61 72 74 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 61 72 74 5f 63 62 74 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 61 72 74 5f 67 65 74 6d 65 73 73 61 67 65 40 40 59 41 48 58 5a 00 3f 68 6f 6f 6b 5f 73 74 6f 70 40 40 59 41 48 58 5a 00 } 		$a_01_1 = {69 73 34 5f 5f 00 00 00 73 79 73 33 30 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}