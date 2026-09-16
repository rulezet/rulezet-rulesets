rule MonitoringTool_AndroidOS_Midros_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Midros.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {6b 65 79 4c 6f 67 67 65 72 } 		$a_00_1 = {2f 61 75 64 69 6f 43 61 6c 6c 73 } 		$a_00_2 = {73 65 6e 64 46 69 6c 65 43 61 6c 6c } 		$a_00_3 = {49 6e 74 65 72 61 63 74 6f 72 53 6d 73 } 		$a_00_4 = {49 6e 74 65 72 61 63 74 6f 72 43 61 6c 6c 73 } 		$a_00_5 = {67 65 74 53 68 6f 77 4f 72 48 69 64 65 41 70 70 } 		$a_00_6 = {67 65 74 4c 6f 63 6b 50 69 6e } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}