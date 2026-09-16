rule MonitoringTool_AndroidOS_Spymob_A_MTB_2{
	meta:
		description = "MonitoringTool:AndroidOS/Spymob.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 00 29 00 38 00 18 00 22 00 6c 00 70 10 3f 01 00 00 1a 02 d9 00 6e 20 43 01 20 00 0c 00 6e 20 43 01 30 00 0c 00 6e 10 44 01 00 00 0c 00 71 20 4a 00 40 00 63 00 21 00 } 		$a_01_1 = {64 65 6c 65 74 65 41 70 70 } 		$a_01_2 = {67 65 74 50 61 63 6b 61 67 65 4e 61 6d 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}