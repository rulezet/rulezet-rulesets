rule MonitoringTool_AndroidOS_CellTracker_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/CellTracker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 74 72 61 63 6b 6d 79 70 68 6f 6e 65 73 2e 63 6f 6d } 		$a_01_1 = {73 74 72 65 65 74 6c 65 6e 73 } 		$a_01_2 = {67 63 6d 63 61 6c 6c 73 6d 73 74 72 61 63 6b 65 72 } 		$a_03_3 = {72 65 6d 6f 74 65 [0-02] 63 65 6c 6c [0-02] 74 72 61 63 6b 65 72 } 		$a_01_4 = {74 72 61 63 6b 79 61 70 70 73 } 		$a_01_5 = {43 65 6c 6c 54 72 61 63 6b 65 72 41 63 74 69 76 69 74 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}