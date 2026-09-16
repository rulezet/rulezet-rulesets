rule MonitoringTool_AndroidOS_MeuSPY_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/MeuSPY.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 65 75 53 50 59 } 		$a_01_1 = {41 75 64 69 6f 52 65 63 6f 72 64 65 72 43 61 6c 6c } 		$a_01_2 = {73 6d 73 2e 74 78 74 } 		$a_01_3 = {74 65 6c 65 66 6f 6e 65 2e 70 68 70 3f 69 64 3d } 		$a_01_4 = {75 70 6c 6f 61 64 76 69 64 65 6f 73 6f 66 66 2e 70 68 70 } 		$a_01_5 = {75 70 6c 6f 61 64 63 6f 6e 74 61 74 6f 2e 70 68 70 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}