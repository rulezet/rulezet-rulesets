rule MonitoringTool_AndroidOS_MobileSpy_2{
	meta:
		description = "MonitoringTool:AndroidOS/MobileSpy,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6f 65 73 20 20 6e 6f 74 20 6d 61 74 63 68 2e 2e 21 21 50 6c 65 61 73 65 20 52 65 2d 65 6e 74 65 72 2e } 		$a_01_1 = {63 61 6c 6c 6c 6f 67 2e 70 68 70 3f } 		$a_00_2 = {6d 6f 62 69 6c 65 73 70 79 } 		$a_01_3 = {72 65 6d 6f 76 65 20 74 68 65 73 65 20 70 65 6f 70 6c 65 3f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}