rule MonitoringTool_Win32_Ardamax_20{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 53 47 2d 39 36 38 43 33 30 34 33 2d 31 31 32 38 2d 34 33 64 63 2d 38 33 41 39 2d 35 35 31 32 32 43 38 44 38 37 43 31 } 		$a_01_1 = {5c 41 6b 6c 5c 6b 68 5c 52 65 6c 65 61 73 65 5c 6b 68 2e 70 64 62 } 		$a_01_2 = {41 4b 4c 2e 30 30 36 } 		$a_01_3 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } 		$a_01_4 = {53 65 74 4b 65 79 48 6f 6f 6b } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=10
 
}