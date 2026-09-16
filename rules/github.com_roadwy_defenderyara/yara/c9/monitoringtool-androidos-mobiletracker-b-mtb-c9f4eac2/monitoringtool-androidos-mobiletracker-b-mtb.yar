rule MonitoringTool_AndroidOS_MobileTracker_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MobileTracker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 6d 73 41 6c 65 72 74 4b 65 79 77 6f 72 64 2e 64 62 } 		$a_00_1 = {53 63 72 65 65 6e 73 68 6f 6f 74 41 63 74 69 76 69 74 79 } 		$a_00_2 = {74 72 61 63 6b 53 6f 63 69 61 6c 4e 65 74 77 6f 72 6b } 		$a_00_3 = {6d 6d 73 2f 69 6e 73 65 72 74 4d 4d 53 56 32 2e 70 68 70 } 		$a_00_4 = {72 65 63 6f 72 64 43 61 6c 6c 73 56 33 2f 69 6e 73 65 72 74 43 61 6c 6c 52 65 63 6f 72 64 } 		$a_00_5 = {47 65 74 4d 65 73 73 61 67 65 57 68 61 74 73 41 70 70 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}