rule MonitoringTool_AndroidOS_Trackplus_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Trackplus.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {74 72 61 63 6b 65 72 70 6c 75 73 2e 64 62 } 		$a_00_1 = {43 6f 6f 72 64 73 4d 61 6e 61 67 65 72 20 72 65 61 64 66 72 6f 6d 44 62 } 		$a_00_2 = {53 70 79 20 61 6e 64 20 53 63 72 65 65 6e 20 4f 6e } 		$a_00_3 = {54 72 61 63 6b 65 72 4c 6f 63 61 74 69 6f 6e 2e 69 73 44 69 73 74 61 6e 63 65 56 61 6c 69 64 } 		$a_00_4 = {4c 72 75 2f 69 6e 74 65 63 68 2f 6c 69 62 2f 54 72 61 63 6b 65 72 53 65 72 76 69 63 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}