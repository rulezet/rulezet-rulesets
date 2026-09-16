rule MonitoringTool_Win32_Ardamax_2{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 4b 4c 4d 57 00 } 		$a_01_1 = {41 4b 4c 2e 30 30 33 00 73 66 78 5f 6d 61 69 6e 00 } 		$a_02_2 = {55 8b ec 51 51 56 57 68 ?? ?? 00 10 33 ff 57 ff 15 ?? ?? 00 10 3b c7 74 0e 57 57 68 65 80 00 00 50 ff 15 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_02_2  & 1)*2) >=6
 
}