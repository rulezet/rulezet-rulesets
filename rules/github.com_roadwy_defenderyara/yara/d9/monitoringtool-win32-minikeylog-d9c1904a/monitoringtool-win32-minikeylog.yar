rule MonitoringTool_Win32_MiniKeyLog{
	meta:
		description = "MonitoringTool:Win32/MiniKeyLog,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 69 6d 70 6c 65 20 6b 65 79 6c 6f 67 67 65 72 20 3c } 		$a_02_1 = {8b c3 0d 00 00 00 40 3b d8 75 6a 68 ?? ?? 40 00 6a 00 e8 ?? ff ff ff 89 45 fc 68 ?? ?? 40 00 e8 ?? ff ff ff } 		$a_00_2 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } 		$a_00_3 = {53 65 74 4b 65 79 48 6f 6f 6b } 		$a_00_4 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } 	condition:
		((#a_00_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}