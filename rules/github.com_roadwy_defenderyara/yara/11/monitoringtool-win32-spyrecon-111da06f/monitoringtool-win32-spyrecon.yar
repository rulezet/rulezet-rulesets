rule MonitoringTool_Win32_SpyRecon{
	meta:
		description = "MonitoringTool:Win32/SpyRecon,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 43 62 74 2e 64 6c 6c } 		$a_01_1 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } 		$a_01_2 = {5c 57 69 6e 43 62 74 5c 52 65 6c 65 61 73 65 5c 57 69 6e 43 62 74 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}