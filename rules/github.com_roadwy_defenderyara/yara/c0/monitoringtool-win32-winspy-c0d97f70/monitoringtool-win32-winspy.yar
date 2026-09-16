rule MonitoringTool_Win32_Winspy{
	meta:
		description = "MonitoringTool:Win32/Winspy,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 2d 53 70 79 20 53 6f 66 74 77 61 72 65 } 		$a_01_1 = {57 69 6e 2d 53 70 79 20 4c 6f 67 69 6e 20 61 6e 64 20 50 61 73 73 77 6f 72 64 } 		$a_01_2 = {77 77 77 2e 77 69 6e 2d 73 70 79 2e 63 6f 6d } 		$a_01_3 = {42 43 20 43 4f 4d 50 55 54 49 4e 47 } 		$a_00_4 = {4b 65 79 6c 6f 67 } 		$a_01_5 = {4b 65 79 53 74 61 74 65 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*3+(#a_00_4  & 1)*2+(#a_01_5  & 1)*2) >=15
 
}