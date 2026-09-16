rule MonitoringTool_AndroidOS_MobileTracker_B_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/MobileTracker.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 76 69 6f 6e 69 6b 61 2f 6d 6f 62 69 76 65 6d 65 6e 74 2f 75 69 2f 63 68 69 6c 64 6d 61 6e 61 67 65 6d 65 6e 74 2f 70 68 6f 6e 65 6f 70 74 69 6f 6e 73 } 		$a_01_1 = {63 68 6d 6f 64 20 25 64 20 25 73 } 		$a_01_2 = {6d 6f 62 69 76 65 6d 65 6e 74 41 67 65 6e 74 55 70 67 72 61 64 65 2e 61 70 6b } 		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 53 65 72 76 69 63 65 } 		$a_01_4 = {69 73 41 64 6d 69 6e 41 63 74 69 76 65 } 		$a_01_5 = {72 65 73 65 74 50 61 73 73 77 6f 72 64 } 		$a_01_6 = {6c 6f 63 6b 4e 6f 77 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}