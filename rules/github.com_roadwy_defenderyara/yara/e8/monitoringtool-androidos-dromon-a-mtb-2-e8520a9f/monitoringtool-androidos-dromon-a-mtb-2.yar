rule MonitoringTool_AndroidOS_Dromon_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Dromon.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {53 65 6e 64 4c 6f 67 73 52 65 63 65 69 76 65 72 } 		$a_00_1 = {43 68 65 63 6b 43 61 6c 6c 4e 75 6d 62 65 72 } 		$a_00_2 = {44 65 6c 43 6f 6d 61 6e 64 53 6d 73 } 		$a_00_3 = {53 65 6e 64 4c 6f 67 46 69 6c 65 73 } 		$a_00_4 = {67 65 74 69 6e 66 6f 2f 54 6f 6f 6c 73 3b } 		$a_00_5 = {4c 63 6f 6d 2f 61 6d 6f 6e 2f 53 6d 73 52 65 63 65 69 76 65 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}