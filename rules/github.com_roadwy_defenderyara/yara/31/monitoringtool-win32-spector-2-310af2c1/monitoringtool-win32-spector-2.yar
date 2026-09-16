rule MonitoringTool_Win32_Spector_2{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {57 61 6e 74 50 4f 53 54 47 4d 61 69 6c [0-30] 6d 61 69 6c 2e 67 6f 6f 67 6c 65 2e 63 6f 6d } 		$a_02_1 = {57 61 6e 74 50 4f 53 54 4f 57 41 [0-30] 2f 6f 77 61 2f 61 75 74 68 2f 6f 77 61 61 75 74 68 2e 64 6c 6c } 		$a_02_2 = {57 61 6e 74 50 4f 53 54 59 61 68 6f 6f [0-30] 6d 61 69 6c 2e 79 61 68 6f 6f 2e } 		$a_00_3 = {53 65 6e 64 4d 65 73 73 61 67 65 00 61 63 74 69 6f 6e 00 00 72 65 71 75 65 73 74 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}