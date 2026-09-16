rule MonitoringTool_AndroidOS_MobileSpy{
	meta:
		description = "MonitoringTool:AndroidOS/MobileSpy,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 62 69 6c 65 4e 61 6e 6e 79 4c 6f 63 6b } 		$a_01_1 = {73 68 6f 77 20 42 6c 6f 63 6b 20 6c 69 73 74 } 		$a_01_2 = {6e 61 6e 6e 79 6c 6f 67 2e 74 78 74 } 		$a_01_3 = {75 70 6c 6f 61 64 69 6e 67 20 67 70 73 2d 2d 3e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}