rule MonitoringTool_AndroidOS_OTSpy_B_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/OTSpy.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 49 4c 45 4e 54 5f 42 41 43 4b 5f 43 41 4d 5f 50 41 53 53 57 4f 52 44 } 		$a_01_1 = {45 72 61 73 65 43 6f 6e 74 61 63 74 73 41 63 74 69 76 69 74 79 } 		$a_01_2 = {72 73 5f 73 69 6c 65 6e 74 5f 76 69 64 65 6f } 		$a_01_3 = {52 45 4d 4f 54 45 5f 43 4f 4e 54 41 43 54 5f 50 41 53 53 57 4f 52 44 } 		$a_03_4 = {63 6f 6d 2e ?? ?? ?? 2e 72 65 6d 6f 74 65 73 65 63 75 72 69 74 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}