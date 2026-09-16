rule MonitoringTool_AndroidOS_AndroRat_2{
	meta:
		description = "MonitoringTool:AndroidOS/AndroRat,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 20 53 4d 53 20 6d 6f 6e 69 74 6f 72 69 6e 67 } 		$a_01_1 = {2a 41 6e 64 72 6f 72 61 74 2e 43 6c 69 65 6e 74 2e 73 74 6f 72 61 67 65 } 		$a_01_2 = {44 41 54 41 5f 4d 4f 4e 49 54 4f 52 5f 43 41 4c 4c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}