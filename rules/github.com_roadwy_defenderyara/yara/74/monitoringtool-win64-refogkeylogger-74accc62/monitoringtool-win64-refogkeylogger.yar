rule MonitoringTool_Win64_RefogKeylogger{
	meta:
		description = "MonitoringTool:Win64/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 70 6b 36 34 2e 64 6c 6c } 		$a_01_1 = {57 4d 5f 49 4d 48 4f 4f 4b 5f 4b 47 } 		$a_01_2 = {57 4d 5f 4d 4f 55 53 45 4d 4f 56 45 48 4f 4f 4b 5f 4b 47 } 		$a_01_3 = {52 65 66 6f 67 20 49 6e 63 } 		$a_01_4 = {47 00 45 00 54 00 20 00 2f 00 69 00 6d 00 2f 00 73 00 65 00 6e 00 64 00 49 00 4d 00 3f 00 63 00 6f 00 6d 00 73 00 63 00 6f 00 72 00 65 00 43 00 68 00 61 00 6e 00 6e 00 65 00 6c 00 } 		$a_01_5 = {3c 00 59 00 6d 00 73 00 67 00 20 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 3d 00 22 00 36 00 22 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*4+(#a_01_5  & 1)*4) >=10
 
}