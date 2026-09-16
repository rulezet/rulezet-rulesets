rule MonitoringTool_Win32_Spector{
	meta:
		description = "MonitoringTool:Win32/Spector,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 65 63 6b 44 6f 63 41 4f 4c 3a 47 65 74 41 64 64 72 65 73 73 65 73 } 		$a_01_1 = {25 32 32 61 63 74 69 6f 6e 25 32 32 25 33 41 25 32 32 53 65 6e 64 4d 65 73 73 61 67 65 25 32 32 } 		$a_01_2 = {43 68 65 63 6b 44 6f 63 47 4d 61 69 6c 3a 43 68 65 63 6b 44 6f 63 45 6d 61 69 6c } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3) >=8
 
}