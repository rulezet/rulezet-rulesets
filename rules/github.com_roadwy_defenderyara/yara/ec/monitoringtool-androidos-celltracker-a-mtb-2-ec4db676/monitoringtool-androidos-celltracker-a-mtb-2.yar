rule MonitoringTool_AndroidOS_CellTracker_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/CellTracker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0f 00 0f 00 08 00 00 "
		
	strings :
		$a_01_0 = {43 41 4c 4c 44 41 54 41 } 		$a_00_1 = {63 6f 6d 2e 6a 79 6f 74 69 6e 2e 63 74 } 		$a_01_2 = {69 73 5f 61 70 70 5f 68 69 64 65 } 		$a_01_3 = {73 6d 73 5f 73 79 6e 63 } 		$a_01_4 = {63 61 6c 6c 5f 6c 6f 67 5f 73 79 6e 63 } 		$a_01_5 = {73 63 72 65 65 6e 5f 63 61 70 74 75 72 65 } 		$a_01_6 = {73 65 6e 64 5f 61 75 64 69 6f 5f 77 69 66 69 } 		$a_01_7 = {6c 61 73 74 5f 73 79 6e 63 5f 63 6f 6e 74 61 63 74 73 5f 63 6f 75 6e 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=15
 
}