rule MonitoringTool_Win32_Spector_4{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 68 69 6c 6c 69 70 2d 2d 47 74 56 65 72 66 79 53 74 6e 67 2d 2d 50 6f 77 65 72 73 } 		$a_01_1 = {50 72 6f 63 65 73 73 4b 65 79 73 74 72 6f 6b 65 46 69 6c 65 31 } 		$a_01_2 = {53 65 74 46 69 6c 65 54 69 6d 65 54 6f 4b 65 72 6e 65 6c 73 5f 48 61 6e 64 6c 65 } 		$a_01_3 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 45 76 65 6e 74 4c 6f 67 5c 41 70 70 6c 69 63 61 74 69 6f 6e 5c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}