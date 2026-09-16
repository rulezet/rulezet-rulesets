rule MonitoringTool_Win32_Ardamax{
	meta:
		description = "MonitoringTool:Win32/Ardamax,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {ba 03 01 00 00 75 12 8b 41 08 d1 e8 40 8d 71 0c 3b c2 } 		$a_02_1 = {56 85 c9 74 0b 8b 71 44 3b 35 ?? ?? ?? ?? 74 0c 8b 31 85 f6 74 12 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}