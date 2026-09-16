rule MonitoringTool_AndroidOS_Trackplus_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Trackplus.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 73 70 79 32 6d 6f 62 69 6c 65 2f 6c 69 67 68 74 } 		$a_00_1 = {67 70 73 5f 72 6f 6f 74 5f 6c 6c } 		$a_00_2 = {54 72 61 63 6b 65 72 4c 6f 63 61 74 69 6f 6e } 		$a_00_3 = {67 65 74 4c 61 73 74 4b 6e 6f 77 6e 4c 6f 63 61 74 69 6f 6e } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}