rule MonitoringTool_MSIL_SimpleKeylogger{
	meta:
		description = "MonitoringTool:MSIL/SimpleKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 69 6d 70 6c 65 4b 65 6c 6f 67 67 65 72 57 69 6e 64 6f 77 73 } 		$a_01_1 = {46 72 6d 5f 53 49 6d 70 6c 65 4c 6f 67 67 65 72 } 		$a_01_2 = {4e 4b 4c 5f 72 65 70 6f 72 74 56 69 77 65 72 } 		$a_01_3 = {43 00 6c 00 69 00 63 00 6b 00 20 00 54 00 6f 00 20 00 76 00 69 00 65 00 77 00 20 00 4b 00 65 00 79 00 53 00 74 00 72 00 6f 00 6b 00 65 00 20 00 52 00 65 00 70 00 6f 00 72 00 74 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}