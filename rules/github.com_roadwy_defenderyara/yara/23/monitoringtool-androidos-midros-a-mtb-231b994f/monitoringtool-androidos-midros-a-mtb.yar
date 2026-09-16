rule MonitoringTool_AndroidOS_Midros_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Midros.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4d 6f 6e 69 74 6f 72 53 65 72 76 69 63 65 } 		$a_00_1 = {73 74 61 72 74 41 70 70 43 68 65 63 6b 65 72 } 		$a_00_2 = {73 6d 73 53 65 72 76 69 63 65 } 		$a_00_3 = {67 65 74 43 61 70 74 75 72 65 50 68 6f 74 6f } 		$a_00_4 = {4c 63 6f 6d 2f 6d 79 2f 73 70 79 2f 61 70 70 2f 72 65 63 65 69 76 65 72 2f 43 61 6c 6c 73 52 65 63 65 69 76 65 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}