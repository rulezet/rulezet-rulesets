rule MonitoringTool_Win32_RefogKeylogger{
	meta:
		description = "MonitoringTool:Win32/RefogKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 70 6b 2e 64 6c 6c 00 } 		$a_01_1 = {57 4d 5f 4b 45 59 48 4f 4f 4b 5f 4b 47 00 } 		$a_03_2 = {8b 44 24 04 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 50 e8 ?? ?? 00 00 83 c4 18 b8 01 00 00 00 c2 04 00 } 		$a_01_3 = {6a 00 56 50 6a 04 ff d7 8b 4c 24 14 6a 00 56 99 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}