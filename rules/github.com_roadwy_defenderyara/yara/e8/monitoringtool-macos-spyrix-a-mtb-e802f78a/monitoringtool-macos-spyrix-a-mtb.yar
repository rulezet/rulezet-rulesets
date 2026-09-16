rule MonitoringTool_MacOS_Spyrix_A_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 73 4d 6f 6e 69 74 6f 72 69 6e 67 4b 65 79 6c 6f 67 67 65 72 } 		$a_01_1 = {69 73 45 6e 61 62 6c 65 41 75 74 6f 43 61 6c 6c 52 65 63 6f 72 64 65 72 } 		$a_01_2 = {6d 6f 6e 69 74 6f 72 2f 64 61 74 61 5f 75 70 6c 6f 61 64 2e 70 68 70 } 		$a_01_3 = {4c 69 76 65 57 65 62 43 61 6d } 		$a_01_4 = {63 6f 6d 2e 73 70 79 72 69 78 2e 73 6b 6d } 		$a_01_5 = {53 63 72 65 65 6e 52 65 63 6f 72 64 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}