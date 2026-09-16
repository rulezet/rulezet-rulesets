rule MonitoringTool_AndroidOS_Spymob_A_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/Spymob.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_00_0 = {73 70 79 32 6d 6f 62 69 6c 65 2e 64 62 } 		$a_00_1 = {6d 6f 62 69 6c 65 73 70 79 } 		$a_00_2 = {54 72 61 63 6b 65 72 53 65 72 76 69 63 65 } 		$a_00_3 = {73 6d 73 5f 68 69 73 74 6f 72 79 } 	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=5
 
}