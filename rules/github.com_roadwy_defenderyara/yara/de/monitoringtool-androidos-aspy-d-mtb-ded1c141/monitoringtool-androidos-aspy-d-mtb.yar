rule MonitoringTool_AndroidOS_Aspy_D_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Aspy.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 6d 73 2e 41 64 64 52 65 63 6f 72 64 } 		$a_01_1 = {52 65 63 6f 72 64 47 70 73 } 		$a_01_2 = {52 65 63 6f 72 64 43 6c 69 70 62 6f 61 72 64 } 		$a_01_3 = {61 2d 73 70 79 } 		$a_01_4 = {41 63 63 53 63 72 65 65 6e 73 68 6f 74 2e 74 61 6b 65 53 63 72 65 65 6e 73 68 6f 74 } 		$a_01_5 = {52 65 63 6f 72 64 53 63 72 65 65 6e 52 6f 6f 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*5+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}