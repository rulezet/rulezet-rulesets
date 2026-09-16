rule MonitoringTool_AndroidOS_MeuSPY_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MeuSPY.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 65 63 65 69 76 65 72 54 65 6c 61 } 		$a_01_1 = {50 72 6f 63 65 73 73 61 72 56 69 64 65 6f 4f 66 66 } 		$a_01_2 = {4c 56 69 64 65 6f 41 63 74 69 76 69 74 79 } 		$a_01_3 = {47 72 61 76 61 72 43 68 61 6d 61 64 61 } 		$a_01_4 = {43 61 6d 65 72 61 46 69 6e 61 6c 69 7a 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}